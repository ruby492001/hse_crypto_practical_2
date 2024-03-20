/// @file
/// @brief Класс для хранение матрицы байтов
#pragma once

#include <vector>


class MatrixRow
{
public:
     MatrixRow( int element_count );
     MatrixRow( const MatrixRow& rhs );
     MatrixRow( const std::vector< unsigned char >& rhs );
     int elementCount() const;

     unsigned char& operator[]( int idx );
     unsigned char operator[]( int idx ) const;
     MatrixRow& operator=( const MatrixRow& rhs );
     MatrixRow& operator=( const std::vector< unsigned char >& rhs );

private:
     std::vector< unsigned char > data_;
};


class Matrix
{
public:
     Matrix( int rowCount, int columnCount );
     Matrix( const Matrix& rhs );
     Matrix( const std::vector< MatrixRow >& rhs );

     int rowCount() const;
     int columnCount() const;

     MatrixRow& operator[]( int idx );
     MatrixRow operator[]( int idx ) const;
     Matrix& operator=( const Matrix& rhs );
     Matrix& operator=( const std::vector< MatrixRow >& rhs );

private:
     std::vector< MatrixRow > data_;
};

