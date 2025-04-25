package org.hasp.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.io.IOException;

@SpringBootApplication
public class AuthorizationServerApplication {

    public static void main(String[] args) throws IOException {
        // todo 测试使用
//        KeyUtils.generateAndSaveKeyPair("D:\\", "default_tenant");
        SpringApplication.run(AuthorizationServerApplication.class, args);
    }

}
