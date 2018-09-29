/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.rocketmq.remoting;

/**
 * 服务启动身边周期执行基本事件封装
 */
public interface RemotingService {
    /**
     * 启动事件
     */
    void start();

    /**
     * 关闭事件
     */
    void shutdown();

    /**
     * 注册一些钩子函数，方便监听，处理强求之前记录信息，请求返回记录信息
     * @param rpcHook
     */
    void registerRPCHook(RPCHook rpcHook);
}
