package com.cebmanagment.userservice.controllers;

import com.cebmanagment.userservice.models.LoginRequest;
import com.cebmanagment.userservice.models.UpdateRoleRequest;
import com.cebmanagment.userservice.models.User;
import lombok.AllArgsConstructor;

import com.cebmanagment.userservice.services.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.GetMapping;
import com.cebmanagment.userservice.config.JwtUtils;

import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@AllArgsConstructor
public class AuthController {
    private final UserService userService;
    private final JwtUtils jwtUtils;


    @PostMapping("/register")
    public String createUser(@RequestBody User user) {
        log.info("Received registration request for user: {}", user.getEmail());
        try {
            userService.createUser(user);
            return "User registered successfully";
        } catch (Exception e) {
            log.error("Registration failed for email: {} with error: {}", user.getEmail(), e.getMessage());
            return e.getMessage();
        }
    }

    @PostMapping("/login")
    public String login(@RequestBody LoginRequest request) {
        try{
            User user = userService.login(request.getEmail(), request.getPassword());
            return jwtUtils.generateJwtToken(user.getEmail(), String.valueOf(user.getRole()));
        } catch (Exception e) {
                  log.error("Login failed for email: {} with error: {}", request.getEmail(), e.getMessage());
            return "Invalid credentials";
        }

    }

    @PutMapping("/{id}/role")
    @PreAuthorize("hasAuthority('ROLE_MANAGER')")
    public String updateUserRole(@PathVariable Long id, @RequestBody UpdateRoleRequest role) {
        try{
             userService.updateUserRole(id, role.getRole());
            return "Role updated successfully";
        }catch (Exception e) {

            return  "Role update Failed  error: " + e.getMessage();
        }

    }
    @PutMapping("/{idNum}/approval")
    @PreAuthorize("hasAnyAuthority('ROLE_SECRETARY', 'ROLE_MANAGER')")
    public String userApproval(@PathVariable Long idNum) {
        try{
            userService.approveUser(idNum);
            return "User was approved successfully";
        }catch (Exception e) {

            return  "Approval Failed  error: " + e.getMessage();
        }

    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('ROLE_MANAGER')")
    public String deleteUser(@PathVariable Long id) {
        try{
            userService.deleteUser(id);
            return "User deleted successfully";
        }
        catch (Exception e) {

            return  "User deletion Failed  error: " + e.getMessage();

        }

    }

    @PutMapping("/{id}")
    public String updateUserInfo(@PathVariable Long id, @RequestBody User user) {
        try {
            userService.updateUserInfo(id, user);
            return "User updated successfully";
        } catch (Exception e) {
            return "User update Failed  error: " + e.getMessage();
        }

    }

    @PutMapping("/{id}/password")
    public String changePassword(@PathVariable Long id, @RequestParam String newPassword) {
        try {
            userService.changePassword(id, newPassword);
            return "Password updated successfully";

        } catch (Exception e) {

            return "Password update Failed  error: " + e.getMessage();
        }

    }

    @PutMapping("/forget-password")
    public String forgetPassword(@RequestBody LoginRequest newPassword) {
        try {
            userService.forgetPassword(newPassword.getEmail(), newPassword.getPassword());
            return "Password updated successfully";
        } catch (Exception e) {
            return "Password update Failed  error: " + e.getMessage();
        }

    }

    @GetMapping
    @PreAuthorize("hasAnyAuthority('ROLE_MANAGER', 'ROLE_SECRETARY', 'ROLE_ACCOUNTANT')")
    public List<User> getAllUsers() {
        return userService.getAllUsers();
    }

}
