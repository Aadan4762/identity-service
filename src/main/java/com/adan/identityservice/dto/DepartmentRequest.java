package com.adan.identityservice.dto;


import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;



@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class DepartmentRequest {

    //@NotBlank(message = "Name shouldn't be null")
    private String name;
}
