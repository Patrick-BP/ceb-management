package com.cebmanagment.userservice.models;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;



public enum Role {
    ROLE_USER,
    ROLE_MANAGER,
    ROLE_SECRETARY,
    ROLE_ACCOUNTANT
}
