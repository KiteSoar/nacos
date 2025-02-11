/*
 * Copyright 1999-$toady.year Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.alibaba.nacos.maintainer.client.auth;

import com.alibaba.nacos.api.PropertyKeyConst;
import com.alibaba.nacos.api.exception.NacosException;
import com.alibaba.nacos.common.utils.StringUtils;
import com.alibaba.nacos.maintainer.client.constants.Constants;
import com.alibaba.nacos.plugin.auth.api.LoginIdentityContext;
import com.alibaba.nacos.plugin.auth.api.RequestResource;
import com.alibaba.nacos.plugin.auth.spi.client.AbstractClientAuthService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Properties;
import java.util.concurrent.TimeUnit;

/**
 * a ClientAuthService implement.
 *
 * @author Nacos
 */
public class MaintainerClientAuthServiceImpl extends AbstractClientAuthService {
    
    private static final Logger LOGGER = LoggerFactory.getLogger(MaintainerClientAuthServiceImpl.class);
    
    public static final String MAINTAINER_CLIENT_AUTH_SERVICE_IMPL = "MAINTAINER_CLIENT_AUTH_SERVICE_IMPL";
    
    /**
     * TTL of token in seconds.
     */
    private long tokenTtl;
    
    /**
     * Last timestamp refresh security info from server.
     */
    private long lastRefreshTime;
    
    /**
     * time window to refresh security info in seconds.
     */
    private long tokenRefreshWindow;
    
    /**
     * A context to take with when sending request to Nacos server.
     */
    private volatile LoginIdentityContext loginIdentityContext = new LoginIdentityContext();
    
    /**
     * Re-login window in milliseconds.
     */
    private final long reLoginWindow = 60000;
    
    /**
     * Login to servers.
     *
     * @return true if login successfully
     */
    
    @Override
    public Boolean login(Properties properties) {
        try {
            boolean reLoginFlag = Boolean.parseBoolean(loginIdentityContext.getParameter(
                    Constants.AuthLoginConstant.RELOGINFLAG, "false"));
            if (reLoginFlag) {
                if ((System.currentTimeMillis() - lastRefreshTime) < reLoginWindow) {
                    return true;
                }
            } else {
                if ((System.currentTimeMillis() - lastRefreshTime) < TimeUnit.SECONDS
                        .toMillis(tokenTtl - tokenRefreshWindow)) {
                    return true;
                }
            }
            
            if (StringUtils.isBlank(properties.getProperty(PropertyKeyConst.USERNAME))) {
                lastRefreshTime = System.currentTimeMillis();
                return true;
            }
            
            for (String server : this.serverList) {
                LoginServiceImpl httpLoginProcessor = new LoginServiceImpl(nacosRestTemplate);
                properties.setProperty(Constants.AuthLoginConstant.SERVER, server);
                LoginIdentityContext identityContext = httpLoginProcessor.login(properties);
                if (identityContext != null) {
                    if (identityContext.getAllKey().contains(Constants.AuthLoginConstant.ACCESSTOKEN)) {
                        tokenTtl = Long.parseLong(identityContext.getParameter(Constants.AuthLoginConstant.TOKENTTL));
                        tokenRefreshWindow = tokenTtl / 10;
                        lastRefreshTime = System.currentTimeMillis();

                        LoginIdentityContext newCtx = new LoginIdentityContext();
                        newCtx.setParameter(Constants.AuthLoginConstant.ACCESSTOKEN,
                                identityContext.getParameter(Constants.AuthLoginConstant.ACCESSTOKEN));
                        this.loginIdentityContext = newCtx;
                    }
                    return true;
                }
            }
        } catch (Throwable throwable) {
            LOGGER.warn("[MaintainerClientAuthService] login failed, error: ", throwable);
            return false;
        }
        return false;
    }
    
    @Override
    public LoginIdentityContext getLoginIdentityContext(RequestResource resource) {
        return this.loginIdentityContext;
    }
    
    @Override
    public String getAuthServiceName() {
        return MAINTAINER_CLIENT_AUTH_SERVICE_IMPL;
    }
    
    @Override
    public void shutdown() throws NacosException {
    
    }
}
