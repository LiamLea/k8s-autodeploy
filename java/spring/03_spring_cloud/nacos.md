# nacos

[toc]

### 概述

#### 1.nacos

##### （1）what
nacos = eureka + config + bus

* 注册中心（自带负载均衡）
* 配置中心
* 消息总线

***

### 部署

```shell
docker run --name nacos-quick -e MODE=standalone -p 8848:8848 -d nacos/nacos-server:2.0.2
```

***

### 客户端使用

#### 1.注册中心

##### （1）引入依赖
```xml
<dependency>
    <groupId>com.alibaba.cloud</groupId>
    <artifactId>spring-cloud-starter-alibaba-nacos-discovery</artifactId>
</dependency>
```

##### （2）修改配置
```yml
spring:
  cloud:
    nacos:
      discovery:
        server-addr: 127.0.0.1:8848
```

##### （3）主函数
```java
@SpringBootApplication
@EnableDiscoveryClient
public class PaymentMain {
    public static void main(String[] args) {
        SpringApplication.run(PaymentMain.class, args);
    }
}
```

#### （4）调用：相应服务名（区分大小写）

#### 2.配置中心

##### （1）引入依赖
```xml
<dependency>
    <groupId>com.alibaba.cloud</groupId>
    <artifactId>spring-cloud-starter-alibaba-nacos-config</artifactId>
</dependency>
<dependency>
    <groupId>com.alibaba.cloud</groupId>
    <artifactId>spring-cloud-starter-alibaba-nacos-discovery</artifactId>
</dependency>
```

##### （2）配置: `bootstrap.yml`
```yaml
spring:
  cloud:
    nacos:
      discovery:
        server-addr: 127.0.0.1:8848
      config:
        prefix: cloud   #如果不加，默认为application name
        server-addr: 127.0.0.1:8848
        file-extension: yaml
```

##### （3）nacos中配置文件命名规则（优先级由高到低）
* `<prefix>-<active>.<file-extension>`
* `<prefix>.<file-extension>`

##### （4）主函数
```java
@SpringBootApplication
@EnableDiscoveryClient
public class ConfigClientMain {
    public static void main(String[] args) {
        SpringApplication.run(ConfigClientMain.class, args);

    }
}
```

##### （5）配置更新

* 使用`@RefreshScope`注解
```java
@RestController
@RefreshScope
public class ConfigClientController {

    @Value("${info}")
    private String configInfo;

    @RequestMapping("/hello")
    public String get_config(){
        return configInfo;
    }
}
```

* 修改nacos中的配置文件，会立即生效