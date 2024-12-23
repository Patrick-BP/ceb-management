package com.cebmanagment.userservice.models;

import io.jsonwebtoken.lang.Assert;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.NoArgsConstructor;

import java.util.Date;
import java.util.Random;
import java.util.UUID;

@Entity
@Data
@AllArgsConstructor
@Table(name = "users")
@NoArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String First_name;
    private String last_name;
    private String gender;
    private Date dob;
    private String status;
    private String institution;
    private String service;
    @Column(unique = true)
    private Long id_number;
    private String phone_number;
    private String address;
    private String city;
    private String country;
    private String postal_code;
    private int approved = 0;
    private int rejected = 0;
    private int added = 0;
    @Email
    private String email;
    private String password;
    @Enumerated(EnumType.STRING)
    private Role role = Role.USER; // Default role is USER

    public enum Role {
        USER,
        MANAGER,
        SECRETARY,
        ACCOUNTANT
    }

    public static long generate8DigitRandomNumber() {
        Random random = new Random(UUID.randomUUID().getMostSignificantBits());
        // Generate a number in the range 10000000 to 99999999
        return 10000000L + Math.abs(random.nextLong() % 90000000L);
    }

    @PrePersist
    public void prePersist() {
        this.id_number = generate8DigitRandomNumber();
    }
}