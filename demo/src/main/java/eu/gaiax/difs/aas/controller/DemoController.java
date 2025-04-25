package eu.gaiax.difs.aas.controller;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping()
public class DemoController {

    private static final Logger log = LoggerFactory.getLogger(DemoController.class);
    
    @GetMapping
    public String root(HttpServletRequest request) {
        return "Hi from app root: " + getIdentity(request);
    }    
    
    @GetMapping("/demo")
    public String demonstrate(HttpServletRequest request) {
        return "Hi from demo app: " + getIdentity(request);
    }    

    @GetMapping("/demo/read")
    public String getBooks(HttpServletRequest request) {
        return "Hi from demo app with read grants: " + getIdentity(request);
    }

    @GetMapping("/demo/write")
    public String getManager(HttpServletRequest request) {
        return "Hi from demo app with write grants: " + getIdentity(request);
    }

    @GetMapping("/logout")
    public String logout(HttpServletRequest request) throws ServletException {
        log.debug("got logout request: {}", request);
        // do logout manually..
        request.logout();
        return "redirect:/demo";
    }

    private String getIdentity(HttpServletRequest request) {
        return request.getUserPrincipal() == null ? null : request.getUserPrincipal().toString();
    }

}

