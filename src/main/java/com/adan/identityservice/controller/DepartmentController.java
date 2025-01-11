package com.adan.identityservice.controller;


import com.adan.identityservice.dto.APIResponse;
import com.adan.identityservice.dto.DepartmentRequest;
import com.adan.identityservice.dto.DepartmentResponse;
import com.adan.identityservice.entity.Department;
import com.adan.identityservice.service.DepartmentService;
import lombok.RequiredArgsConstructor;
import org.springframework.data.domain.Page;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.List;



@RestController
@RequestMapping("/api/v2/department")
@RequiredArgsConstructor
public class DepartmentController {

    private final DepartmentService departmentService;

    @PostMapping("/create")
    @ResponseStatus(HttpStatus.CREATED)
    public ResponseEntity<String> createDepartment(@RequestBody @Validated DepartmentRequest departmentRequest) {
        try {
            departmentService.addDepartment(departmentRequest);
            return ResponseEntity.status(HttpStatus.CREATED).body("Department created successfully");
        } catch (Exception exception) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Failed to create department: " + exception.getMessage());
        }
    }

    @GetMapping("/all")
    @ResponseStatus(HttpStatus.OK)
    public List<DepartmentResponse> getAllDepartment() {
        return departmentService.getAllDepartment();
    }

    @GetMapping("/{id}")
    public ResponseEntity<Object> getDepartmentById(@PathVariable int id) {
        try {
            DepartmentResponse department = departmentService.getDepartmentById(id);
            return ResponseEntity.ok(department);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Department not found");
        }
    }

    @PutMapping("/{id}")
    public ResponseEntity<String> updateDepartmentById(@PathVariable int id, @RequestBody DepartmentRequest departmentRequest) {
        try {
            boolean isUpdated = departmentService.updateDepartment(id, departmentRequest);
            if (isUpdated) {
                return ResponseEntity.ok("Department updated successfully");
            } else {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Department update failed");
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to update department: " + e.getMessage());
        }
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public ResponseEntity<String> deleteDepartmentById(@PathVariable int id) {
        try {
            boolean isDeleted = departmentService.deleteDepartmentById(id);
            if (isDeleted) {
                return ResponseEntity.ok("Department deleted successfully");
            } else {
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body("Department not found");
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Failed to delete department: " + e.getMessage());
        }
    }

    @GetMapping("/sort/{field}")
    public APIResponse<List<Department>> getDepartmentsWithSort(@PathVariable String field) {
        List<Department> allDepartments = departmentService.findDepartmentsWithSorting(field);
        return new APIResponse<>(allDepartments.size(), allDepartments);
    }

    @GetMapping("/pagination/{offset}/{pageSize}")
    public APIResponse<Page<Department>> getDepartmentsWithPagination(@PathVariable int offset, @PathVariable int pageSize) {
        Page<Department> departmentsWithPagination = departmentService.findDepartmentsWithPagination(offset, pageSize);
        return new APIResponse<>(departmentsWithPagination.getSize(), departmentsWithPagination);
    }

    @GetMapping("/paginationAndSort/{offset}/{pageSize}/{field}")
    public APIResponse<Page<Department>> getDepartmentsWithPaginationAndSort(@PathVariable int offset, @PathVariable int pageSize, @PathVariable String field) {
        Page<Department> departmentsWithPagination = departmentService.findDepartmentsWithPaginationAndSorting(offset, pageSize, field);
        return new APIResponse<>(departmentsWithPagination.getSize(), departmentsWithPagination);
    }
}
