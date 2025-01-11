package com.adan.identityservice.service;


import com.adan.identityservice.dto.DepartmentRequest;
import com.adan.identityservice.dto.DepartmentResponse;
import com.adan.identityservice.entity.Department;
import org.springframework.data.domain.Page;

import java.util.List;

public interface DepartmentService {

    List<DepartmentResponse> getAllDepartment();
    DepartmentResponse getDepartmentById(int id);
    void addDepartment(DepartmentRequest departmentRequest);
    boolean updateDepartment(int id, DepartmentRequest departmentRequest);
    boolean deleteDepartmentById(int id);
    List<Department> findDepartmentsWithSorting(String field);
    Page<Department> findDepartmentsWithPagination(int offset, int pageSize);
    Page<Department> findDepartmentsWithPaginationAndSorting(int offset, int pageSize, String field);
}
