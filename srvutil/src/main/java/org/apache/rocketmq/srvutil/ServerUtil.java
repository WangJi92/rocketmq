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
package org.apache.rocketmq.srvutil;

import java.util.Properties;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

/**
 * 了解命令行参数的使用，这个感觉就是最佳的实践
 * [Apache Commons CLI命令行启动](http://www.cnblogs.com/xing901022/p/5608823.html)
 */
public class ServerUtil {

    /**
     * [Apache Commons CLI命令行启动](http://www.cnblogs.com/xing901022/p/5608823.html)
     * 根据common.cli 构建 命令行参数
     * @param options
     * @return
     */
    public static Options buildCommandlineOptions(final Options options) {
        Option opt = new Option("h", "help", false, "Print help");
        opt.setRequired(false);
        options.addOption(opt);

        opt =
            new Option("n", "namesrvAddr", true,
                "Name server address list, eg: 192.168.0.1:9876;192.168.0.2:9876");
        opt.setRequired(false);
        options.addOption(opt);

        return options;
    }

    /**
     * [Apache Commons CLI命令行启动](http://www.cnblogs.com/xing901022/p/5608823.html)
     * 解析命令行参数，如果输入h 打印帮助的信息
     * @param appName  当前应用的名称用来提示使用的
     *
     *  usage: testApp [-c <arg>] [-h] [-p]
     *  -c,--configFile <arg>   Name server config properties file
     *  -h,--help               Print help
     *  -p,--printConfigItem    Print all config item
     * --------------------------------------
     * @param args
     * @param options
     * @param parser
     * @return
     */
    public static CommandLine parseCmdLine(final String appName, String[] args, Options options,
        CommandLineParser parser) {
        //打印命令行参数帮助信息
        HelpFormatter hf = new HelpFormatter();
        hf.setWidth(110);
        CommandLine commandLine = null;
        try {
            commandLine = parser.parse(options, args);
            if (commandLine.hasOption('h')) {
                hf.printHelp(appName, options, true);
                return null;
            }
        } catch (ParseException e) {
            hf.printHelp(appName, options, true);
        }

        return commandLine;
    }

    /**
     * 答应命令行的帮助信息
     * @param appName
     * @param options
     */
    public static void printCommandLineHelp(final String appName, final Options options) {
        HelpFormatter hf = new HelpFormatter();
        hf.setWidth(110);
        hf.printHelp(appName, options, true);
    }

    /**
     * 获取命令行参数中的值，然后帮助成为Properties 属性哦
     * @param commandLine
     * @return
     */
    public static Properties commandLine2Properties(final CommandLine commandLine) {
        Properties properties = new Properties();
        Option[] opts = commandLine.getOptions();

        if (opts != null) {
            for (Option opt : opts) {
                String name = opt.getLongOpt();
                String value = commandLine.getOptionValue(name);
                if (value != null) {
                    properties.setProperty(name, value);
                }
            }
        }

        return properties;
    }

}
