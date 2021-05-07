package com.example.gateway.controllers;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloWorldController {

    @GetMapping("/helloworld")
    public String helloworld() {
        return "Hello world";
    }

    @GetMapping("/goodbyeworld")
    public String goodbuyworld() {
        return "Goodbye world";
    }
}
