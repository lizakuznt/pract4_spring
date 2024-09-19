package com.example.pract_4.controllers;

import com.example.pract_4.models.ModelUser;
import com.example.pract_4.models.RoleEnum;
import com.example.pract_4.repos.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

@Controller
public class PublicController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/home")
    public String home(Model model, Principal principal) {
        if (principal == null) {
            return "redirect:/login";
        }

        String username = principal.getName();
        ModelUser user = userRepository.findByUsername(username);

        model.addAttribute("username", username);

        if (user.getRoles().contains(RoleEnum.ADMIN)) {
            model.addAttribute("userRole", "ADMIN");
        } else if (user.getRoles().contains(RoleEnum.USER)) {
            model.addAttribute("userRole", "USER");
        }

        return "home";
    }
}
