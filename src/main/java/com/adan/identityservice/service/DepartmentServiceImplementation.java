package com.adan.identityservice.service;

import com.adan.identityservice.dto.DepartmentRequest;
import com.adan.identityservice.dto.DepartmentResponse;
import com.adan.identityservice.entity.Department;
import com.adan.identityservice.exception.DepartmentNotFoundException;
import com.adan.identityservice.repository.DepartmentRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class DepartmentServiceImplementation implements DepartmentService {

    private final DepartmentRepository departmentRepository;

    @Override
    public List<DepartmentResponse> getAllDepartment() {
        List<Department> departments = departmentRepository.findAll();
        return departments.stream()
                .map(this::mapToDepartmentResponse)
                .collect(Collectors.toList());
    }

    @Override
    public DepartmentResponse getDepartmentById(int id) {
        Optional<Department> departmentOptional = departmentRepository.findById(id);
        return departmentOptional.map(this::mapToDepartmentResponse)
                .orElseThrow(() -> new DepartmentNotFoundException("Department with ID " + id + " not found"));
    }

    @Override
    public void addDepartment(DepartmentRequest departmentRequest) {
        Department department = new Department();
        department.setName(departmentRequest.getName());
        departmentRepository.save(department);
    }

    @Override
    public boolean updateDepartment(int id, DepartmentRequest departmentRequest) {
        Optional<Department> existingDepartmentOptional = departmentRepository.findById(id);
        return existingDepartmentOptional.map(existingDepartment -> {
            existingDepartment.setName(departmentRequest.getName());
            departmentRepository.save(existingDepartment);
            log.info("Department {} is updated", existingDepartment.getId());
            return true;
        }).orElseGet(() -> {
            log.error("Department with id {} not found, update failed", id);
            return false;
        });
    }

    @Override
    public boolean deleteDepartmentById(int id) {
        Optional<Department> departmentOptional = departmentRepository.findById(id);
        return departmentOptional.map(department -> {
            departmentRepository.delete(department);
            log.info("Department {} is deleted", department.getId());
            return true;
        }).orElse(false);
    }

    private DepartmentResponse mapToDepartmentResponse(Department department) {
        return DepartmentResponse.builder()
                .id(department.getId())
                .name(department.getName())
                .build();
    }

    public List<Department> findDepartmentsWithSorting(String field) {
        return departmentRepository.findAll(Sort.by(Sort.Direction.ASC, field));
    }

    public Page<Department> findDepartmentsWithPagination(int offset, int pageSize) {
        return departmentRepository.findAll(PageRequest.of(offset, pageSize));
    }

    public Page<Department> findDepartmentsWithPaginationAndSorting(int offset, int pageSize, String field) {
        return departmentRepository.findAll(PageRequest.of(offset, pageSize, Sort.by(field)));
    }
}
