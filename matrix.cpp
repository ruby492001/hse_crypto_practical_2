/// @file
/// @brief Класс для хранение матрицы байтов

#include "matrix.h"

#include <stdexcept>

MatrixRow::MatrixRow( int element_count )
{
     data_.resize( element_count );
}


MatrixRow::MatrixRow( const MatrixRow& rhs )
{
     *this = rhs;
}


MatrixRow::MatrixRow( const std::vector< unsigned char >& rhs )
{
     *this = rhs;
}


int MatrixRow::elementCount() const
{
     return data_.size();
}


unsigned char& MatrixRow::operator[]( int idx )
{
     return data_[ idx ];
}


unsigned char MatrixRow::operator[]( int idx ) const
{
     return data_[ idx ];
}


MatrixRow& MatrixRow::operator=( const MatrixRow& rhs )
{
     data_ = rhs.data_;
     return *this;
}


MatrixRow& MatrixRow::operator=( const std::vector<unsigned char>& rhs )
{
     data_.resize( rhs.size() );
     for( int idx = 0; idx < data_.size(); idx++ )
     {
          data_[ idx ] = rhs[ idx ];
     }
     return *this;
}


Matrix::Matrix( int rowCount, int columnCount )
{
     data_.reserve( rowCount );
     for( ; rowCount > 0; rowCount-- )
     {
          data_.emplace_back( MatrixRow( columnCount ) );
     }
}


Matrix::Matrix( const Matrix& rhs )
{
     *this = rhs;
}


Matrix::Matrix( const std::vector< MatrixRow >& rhs )
{
     *this = rhs;
}


int Matrix::rowCount() const
{
     return data_.size();
}


int Matrix::columnCount() const
{
     if( data_.empty() )
     {
          return 0;
     }
     return data_.begin()->elementCount();
}


MatrixRow& Matrix::operator[]( int idx )
{
     return data_[ idx ];
}

MatrixRow Matrix::operator[]( int idx ) const
{
     return data_[ idx ];
}


Matrix& Matrix::operator=( const Matrix& rhs )
{
     data_ = rhs.data_;
     return *this;
}


Matrix& Matrix::operator=( const std::vector< MatrixRow >& rhs )
{
     if( rhs.empty() )
     {
          return *this;
     }
     int rowCount = rhs.begin()->elementCount();
     for( const auto& row: rhs )
     {
          if( row.elementCount() != rowCount )
          {
               throw std::runtime_error( "all row must be same size" );
          }
          data_.push_back( row );
     }

     return *this;
}
