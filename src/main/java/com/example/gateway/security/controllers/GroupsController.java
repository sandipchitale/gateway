package com.example.gateway.security.controllers;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import com.example.gateway.security.GroupsProvider;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class GroupsController implements ApplicationContextAware {
    Map<String, GroupsProvider> groupsProvidersMap;

    @GetMapping("/groups")
    public List<String> groups() {
        List<String> allGroups = groupsProvidersMap
                .values()
                .stream()
                .flatMap(groupsProvider -> groupsProvider.getGroups().stream())
                .collect(Collectors.toList());
        return Collections.unmodifiableList(allGroups);
    }

    @Override
    public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
        groupsProvidersMap = applicationContext.getBeansOfType(GroupsProvider.class);
    }

}
