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
package org.apache.rocketmq.remoting.netty;

import io.netty.channel.Channel;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.rocketmq.remoting.InvokeCallback;
import org.apache.rocketmq.remoting.common.SemaphoreReleaseOnlyOnce;
import org.apache.rocketmq.remoting.protocol.RemotingCommand;

/**
 * 异步响应处理，并不是直接的响应哦！
 */
public class ResponseFuture {
    /**
     * 每个消息的唯一标志
     */
    private final int opaque;
    /**
     *当前处理的通道信息
     */
    private final Channel processChannel;
    /**
     * 超时处理
     */
    private final long timeoutMillis;
    /**
     * 执行完回调接口信息
     */
    private final InvokeCallback invokeCallback;
    /**
     * 开始时间
     */
    private final long beginTimestamp = System.currentTimeMillis();
    /**
     * [CountDownLatch使用之等待超时](https://blog.csdn.net/sidongxue2/article/details/71727768)
     * 超时之后不会阻塞，继续执行下面的逻辑
     */
    private final CountDownLatch countDownLatch = new CountDownLatch(1);

    /**
     * 只使用一次的，但是感觉内部的属性也是无法获取的
     */
    private final SemaphoreReleaseOnlyOnce once;

    /**
     * 只执行回调一次代码
     */
    private final AtomicBoolean executeCallbackOnlyOnce = new AtomicBoolean(false);
    /**
     * 响应命令的信息
     */
    private volatile RemotingCommand responseCommand;

    /**
     * 发送请求成功
     */
    private volatile boolean sendRequestOK = true;

    /**
     * 异常的原因
     */
    private volatile Throwable cause;

    public ResponseFuture(Channel channel, int opaque, long timeoutMillis, InvokeCallback invokeCallback,
        SemaphoreReleaseOnlyOnce once) {
        this.opaque = opaque;
        this.processChannel = channel;
        this.timeoutMillis = timeoutMillis;
        this.invokeCallback = invokeCallback;
        this.once = once;
    }

    /**
     * 执行回调函数的处理{@link InvokeCallback}
     */
    public void executeInvokeCallback() {
        if (invokeCallback != null) {
            if (this.executeCallbackOnlyOnce.compareAndSet(false, true)) {
                invokeCallback.operationComplete(this);
            }
        }
    }

    public void release() {
        if (this.once != null) {
            /**
             * 信号量使用减少一次
             */
            this.once.release();
        }
    }

    /**
     * 是否超时检测
     * @return
     */
    public boolean isTimeout() {
        long diff = System.currentTimeMillis() - this.beginTimestamp;
        return diff > this.timeoutMillis;
    }

    /**
     * 多久之后返回响应
     * @param timeoutMillis
     * @return
     * @throws InterruptedException
     */
    public RemotingCommand waitResponse(final long timeoutMillis) throws InterruptedException {
        this.countDownLatch.await(timeoutMillis, TimeUnit.MILLISECONDS);
        return this.responseCommand;
    }

    /**
     * 直接响应处理，触发上面的await处理函数
     * @param responseCommand
     */
    public void putResponse(final RemotingCommand responseCommand) {
        this.responseCommand = responseCommand;
        this.countDownLatch.countDown();
    }

    public long getBeginTimestamp() {
        return beginTimestamp;
    }

    public boolean isSendRequestOK() {
        return sendRequestOK;
    }

    public void setSendRequestOK(boolean sendRequestOK) {
        this.sendRequestOK = sendRequestOK;
    }

    public long getTimeoutMillis() {
        return timeoutMillis;
    }

    public InvokeCallback getInvokeCallback() {
        return invokeCallback;
    }

    public Throwable getCause() {
        return cause;
    }

    public void setCause(Throwable cause) {
        this.cause = cause;
    }

    public RemotingCommand getResponseCommand() {
        return responseCommand;
    }

    public void setResponseCommand(RemotingCommand responseCommand) {
        this.responseCommand = responseCommand;
    }

    public int getOpaque() {
        return opaque;
    }

    public Channel getProcessChannel() {
        return processChannel;
    }

    @Override
    public String toString() {
        return "ResponseFuture [responseCommand=" + responseCommand
            + ", sendRequestOK=" + sendRequestOK
            + ", cause=" + cause
            + ", opaque=" + opaque
            + ", processChannel=" + processChannel
            + ", timeoutMillis=" + timeoutMillis
            + ", invokeCallback=" + invokeCallback
            + ", beginTimestamp=" + beginTimestamp
            + ", countDownLatch=" + countDownLatch + "]";
    }
}
