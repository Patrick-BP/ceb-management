package com.cebmanagment.userservice.services;


import com.cebmanagment.userservice.models.User;

import java.util.List;

public interface UserService {
    void createUser(User user);
    void updateUserRole(Long userId, User.Role role);
    void approveUser(Long id_number);
    void deleteUser(Long userId);
    void updateUserInfo(Long userId, User user);
    void changePassword(Long userId, String newPassword);
    void forgetPassword(String email, String newPassword);
    User login(String email, String password);
    List<User> getAllUsers();
}