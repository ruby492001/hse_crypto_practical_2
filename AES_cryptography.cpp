#include "AES_cryptography.h"

#include <stdexcept>
#include <cstring>
#include <iostream>
#include <random>

using namespace std;

AESCryptography::AESCryptography( AesKeyLength keyLength )
:Nk( calculateNk( keyLength ) ), Nr( calculateNr( keyLength ) )
{
     // Nr и Nk зависят от размера ключа -> рассчитываем их при создании объекта в зависимости от размера ключа
}


vector< unsigned char > AESCryptography::cryptDataECB( const vector< unsigned char >& data, const std::vector< unsigned char >& key )
{
     // проверяем, что входные данные могут быть разбиты на блоки по oneBlockSize. Если нет - исключение
     if( data.size() % oneBlockSize != 0 )
     {
          throw runtime_error( "data is not aligned" );
     }

     // создаем набор раундовых ключей, которые исользуются для шифрования
     Matrix roundKeyMatrix = KeyExpansion( key );

     // последовательно шифруем блоки открытого текста и шифртекст записываем в result
     std::vector< unsigned char > result;
     for( int block = 0; block < data.size(); block+= oneBlockSize )
     {
          std::vector< unsigned char > tmp = cryptBlock( { data.begin() + block, data.begin() + block + 16 }, roundKeyMatrix );
          result.insert( result.end(), std::make_move_iterator( tmp.begin() ), std::make_move_iterator( tmp.end() ) );
     }
     return result;
}


std::vector<unsigned char> AESCryptography::cryptDataCBC( const vector<unsigned char>& data, const vector<unsigned char>& key,
                                                           const vector<unsigned char>& iv )
{
     if( data.size() % 16 != 0 )
     {
          throw runtime_error( "data is not aligned" );
     }
     // проверяем, что размер вектора инициализации равен размеру блока открытого текста. Если нет -> исключение
     // вектор инициализации в этом режиме используется для выполнения операции XOR над первым блоком открытого текста(т.к. первый блок не может выполнить
     // операцию XOR над предыдущим блоком шифртекста
     if( iv.size() != oneBlockSize )
     {
          throw runtime_error( "iv has not valid size" );
     }

     // храним предыдущий блок шифртекста. Для первого блока используем IV
     std::vector< unsigned char > lastEncryptedData = iv;
     Matrix roundKeysMatrix = KeyExpansion( key );

     std::vector< unsigned char > result;
     for( int block = 0; block < data.size(); block+= 16 )
     {
          std::vector< unsigned char > src( data.begin() + block, data.begin() + block + 16 );

          // выполняем операцию XOR над последним блоком шифртекста и текущим открытым текстом
          src = vector_xor( src, lastEncryptedData );
          std::vector< unsigned char > tmp_result = cryptBlock( src, roundKeysMatrix );

          // записываем текущий блок шифртекста для использования при шифровании следующего блока
          lastEncryptedData = tmp_result;

          result.insert( result.end(), std::make_move_iterator( tmp_result.begin() ), std::make_move_iterator( tmp_result.end() ) );
     }

     return result;
}


std::vector< unsigned char > AESCryptography::cryptBlock( const vector< unsigned char >& data, const Matrix& roundKeysMatrix )
{
     // проверям размер блока
     if( data.size() != oneBlockSize )
     {
          throw runtime_error( "invalid block size" );
     }

     // создаем матрицу, содержащую в себе открытый текст. С ней будем работать при шифровании и затем преобразуем обратной в массив байт
     Matrix dataMatrix = block_to_matrix_4x4( data );

     // выполняем операции для шифрования из стандарта(п. 5.1, стр 15)
     int round_key_idx = 0;
     addRoundKey( dataMatrix, roundKeysMatrix, round_key_idx );
     round_key_idx += 4;

     for( int round = 0; round < Nr - 1; round++ )
     {
          subBytes( dataMatrix );
          shiftRows( dataMatrix );
          mixColumn( dataMatrix );
          addRoundKey( dataMatrix, roundKeysMatrix, round_key_idx );
          round_key_idx += 4;
     }

     subBytes( dataMatrix );
     shiftRows( dataMatrix );
     addRoundKey( dataMatrix, roundKeysMatrix, round_key_idx );


     return matrix_4_4_to_vector( dataMatrix );
}


std::vector< unsigned char > AESCryptography::decryptDataECB( const std::vector< unsigned char >& data, const std::vector< unsigned char >& key )
{
     if( data.size() % 16 != 0 )
     {
          throw runtime_error( "data is not aligned" );
     }

     Matrix roundKeyMatrix = KeyExpansion( key );

     std::vector< unsigned char > result;
     for( int block = 0; block < data.size(); block+= 16 )
     {
          std::vector< unsigned char > tmp = decryptBlock( { data.begin() + block, data.begin() + block + 16 }, roundKeyMatrix );
          result.insert( result.end(), std::make_move_iterator( tmp.begin() ), std::make_move_iterator( tmp.end() ) );
     }

     return result;
}

std::vector<unsigned char> AESCryptography::decryptDataCBC( const std::vector<unsigned char>& data, const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv )
{
     if( data.size() % 16 != 0 )
     {
          throw runtime_error( "data is not aligned" );
     }

     Matrix roundKeyMatrix = KeyExpansion( key );

     std::vector< unsigned char > last_encrypted_data = iv;

     std::vector< unsigned char > result;
     for( int block = 0; block < data.size(); block+= 16 )
     {
          std::vector< unsigned char > src( data.begin() + block, data.begin() + block + 16 );
          std::vector< unsigned char > tmp = decryptBlock( src, roundKeyMatrix );
          tmp = vector_xor( tmp, last_encrypted_data );
          last_encrypted_data = src;
          result.insert( result.end(), std::make_move_iterator( tmp.begin() ), std::make_move_iterator( tmp.end() ) );
     }

     return result;
}


std::vector< unsigned char > AESCryptography::decryptBlock( const std::vector<unsigned char>& data, const Matrix& roundKeysMatrix )
{
     if( data.size() != 16 )
     {
          throw runtime_error( "invalid block size" );
     }

     Matrix dataMatrix = block_to_matrix_4x4( data );

     int roundKeyIdx = ( ( Nr + 1 ) ) * Nb - 4;

     addRoundKey( dataMatrix, roundKeysMatrix, roundKeyIdx );
     roundKeyIdx -= 4;

     for( int round = Nr - 1; round > 0; round-- )
     {
          invShiftRows( dataMatrix );
          invSubBytes( dataMatrix );
          addRoundKey( dataMatrix, roundKeysMatrix, roundKeyIdx );
          roundKeyIdx -= 4;
          invMixColumn( dataMatrix );
     }

     invShiftRows( dataMatrix );
     invSubBytes( dataMatrix );
     addRoundKey( dataMatrix, roundKeysMatrix, roundKeyIdx );


     return matrix_4_4_to_vector( dataMatrix );
}


Matrix AESCryptography::block_to_matrix_4x4( const vector< unsigned char >& data )
{
     Matrix result( 4, 4 );

     for( int idx = 0; idx < data.size(); idx++ )
     {
          result[ idx % 4 ][ idx / 4 ] = data[ idx ];
     }
     return result;
}


void AESCryptography::subBytes( Matrix& matrix )
{
     for( int row = 0; row < matrix.rowCount(); row++ )
     {
          for( int column = 0; column < matrix.columnCount(); column++ )
          {
               matrix[ row ][ column ]= sboxValue( matrix[ row ][ column ], sbox );
          }
     }
}


void AESCryptography::shiftRows( Matrix& matrix )
{
     for( int row = 0; row < 4; row++ )
     {
          int shift_count = row;
          while( shift_count != 0 )
          {
               unsigned char first_byte = matrix[ row ][ 0 ];
               for( int idx = 1; idx < 4; idx++ )
               {
                    matrix[ row ][ idx - 1 ] = matrix[ row ][ idx ];
               }
               matrix[ row ][ 3 ] = first_byte;
               shift_count--;
          }
     }
}


void AESCryptography::mixColumn( Matrix& matrix )
{
     for( int column = 0; column < 4; column++ )
     {
          unsigned char tmp_column[4];
          for( int row = 0; row < 4; row++ )
          {
               tmp_column[ row ] = multiplyBytes( mixColumnsMatrix[ row ][ 0 ],  matrix[ 0 ][ column ] ) ^
                                   multiplyBytes( mixColumnsMatrix[ row ][ 1 ],  matrix[ 1 ][ column ] ) ^
                                   multiplyBytes( mixColumnsMatrix[ row ][ 2 ],  matrix[ 2 ][ column ] ) ^
                                   multiplyBytes( mixColumnsMatrix[ row ][ 3 ],  matrix[ 3 ][ column ] );
          }

          for( int row = 0; row < 4; row++ )
          {
               matrix[ row ][ column ] = tmp_column[ row ];
          }
     }
}


unsigned char AESCryptography::multiplyBytes( unsigned char a, unsigned char b )
{
     unsigned char result = 0;
     unsigned char high_bit_set;
     for (int i = 0; i < 8; ++i) {
          if (b & 1) {
               result ^= a;
          }
          high_bit_set = (a & 0x80);
          a <<= 1;
          if (high_bit_set) {
               a ^= 0x1b;
          }
          b >>= 1;
     }
     return result;
}


Matrix AESCryptography::KeyExpansion( const vector< unsigned char >& key )
{
     if( key.size() != Nk * 4 )
     {
          throw runtime_error( "invalid key size" );
     }

     // сохдаем матрицу раундовых ключей с размеров столбца в зависимости от размеры ключа
     Matrix result( 4, Nb * ( Nr + 1 ) );

     // заполняем первый раундовый ключ переданным ключом
     for( int row = 0; row < 4; row++ )
     {
          for( int column = 0; column < Nk; column++ )
          {
               result[ row ][ column ] = key[ row + 4 * column ];
          }
     }

     // заполняем матрицу в соответствии со стандартом(п 5.2, стр.19)
     for( int column = Nk; column < result.columnCount(); column++ )
     {
          if( column % Nk == 0 )
          {
               unsigned char tmp_column[ 4 ];
               shiftColumn( result, column - 1, 1, tmp_column );

               for( int row = 0; row < 4; row++ )
               {
                    tmp_column[ row ] = sboxValue( tmp_column[ row ], sbox );
               }
               for( int row = 0; row < 4; row++ )
               {
                    result[ row ][ column ] = result[ row ][ column - Nk ] ^ tmp_column[ row ] ^
                            rcon( row, column / Nk - 1 );
               }
          }
          else if( Nk > 6 && column % Nk == 4 )
          {
               for( int row = 0; row < 4; row++ )
               {
                    result[ row ][ column ] = result[ row ][ column - Nk ] ^ sboxValue( result[ row ][ column - 1 ], sbox );
               }
          }
          else
          {
               for( int row = 0; row < 4; row++ )
               {
                    result[ row ][ column ] = result[ row ][ column - Nk ] ^ result[ row ][ column - 1 ];
               }
          }
     }
     return result;
}


void AESCryptography::shiftColumn( const Matrix& matrix, int column, int shift, unsigned char result[ 4 ] )
{
     for( int row = 0; row < 4; row++ )
     {
          result[ row ] = matrix[ row ][ column ];
     }
     while( shift != 0 )
     {
          int top_item = result[ 0 ];
          for( int row = 0; row < 3; row++ )
          {
               result[ row ] = result[ row + 1 ];
          }
          result[ 3 ] = top_item;
          shift--;
     }
}


unsigned char AESCryptography::rcon( int row, int column )
{
     if( row != 0 )
     {
          return 0;
     }
     if( column == 8 )
     {
          return 0x1b;
     }
     if( column == 9 )
     {
          return 0x36;
     }
     return ( 1 << column );
}


void AESCryptography::addRoundKey( Matrix& matrix, const Matrix& round_keys_matrix, int first_column )
{
     for( int row = 0; row < matrix.rowCount(); row++ )
     {
          for( int column = 0; column < matrix.columnCount(); column++ )
          {
               matrix[ row ][ column ] ^= round_keys_matrix[ row ][ column + first_column ];
          }
     }
}


std::vector< unsigned char > AESCryptography::matrix_4_4_to_vector( const Matrix& matrix )
{
     std::vector< unsigned char > result;
     result.resize( 4 * Nb );
     for( int row = 0; row < 4; row++ )
     {
          for( int column = 0; column < Nb; column++ )
          {
               result[ row + 4 * column ] = matrix[ row ][ column ];
          }
     }
     return result;
}



void AESCryptography::invSubBytes( Matrix& matrix )
{
     for( int row = 0; row < matrix.rowCount(); row++ )
     {
          for( int column = 0; column < matrix.columnCount(); column++ )
          {
               matrix[ row ][ column ]= sboxValue( matrix[ row ][ column ], invSbox );
          }
     }
}


void AESCryptography::invShiftRows( Matrix& matrix )
{
     for( int row = 0; row < 4; row++ )
     {
          int shift_count = row;
          while( shift_count != 0 )
          {
               unsigned char first_byte = matrix[ row ][ 3 ];
               for( int idx = 3; idx > 0; idx-- )
               {
                    matrix[ row ][ idx ] = matrix[ row ][ idx - 1 ];
               }
               matrix[ row ][ 0 ] = first_byte;
               shift_count--;
          }
     }
}


void AESCryptography::invMixColumn( Matrix& matrix )
{
     for( int column = 0; column < 4; column++ )
     {
          unsigned char tmp_column[4];
          for( int row = 0; row < 4; row++ )
          {
               tmp_column[ row ] = multiplyBytes( invMixColumnsMatrix[ row ][ 0 ],  matrix[ 0 ][ column ] ) ^
                                   multiplyBytes( invMixColumnsMatrix[ row ][ 1 ],  matrix[ 1 ][ column ] ) ^
                                   multiplyBytes( invMixColumnsMatrix[ row ][ 2 ],  matrix[ 2 ][ column ] ) ^
                                   multiplyBytes( invMixColumnsMatrix[ row ][ 3 ],  matrix[ 3 ][ column ] );
          }

          for( int row = 0; row < 4; row++ )
          {
               matrix[ row ][ column ] = tmp_column[ row ];
          }
     }
}

std::vector< unsigned char > AESCryptography::vector_xor( const vector<unsigned char>& lhs, const vector<unsigned char>& rhs )
{
     if( lhs.size() != rhs.size() )
     {
          throw std::runtime_error( "could not xor vectors with different size" );
     }

     std::vector< unsigned char > result;
     result.resize( lhs.size() );
     for( int idx = 0; idx < lhs.size(); idx++ )
     {
          result[ idx ] = lhs[ idx ] ^ rhs[ idx ];
     }
     return result;
}


std::vector<unsigned char> AESCryptography::create_iv()
{
     std::vector<unsigned char > result;
     std::random_device dev;
     std::mt19937 rng(dev());
     std::uniform_int_distribution<std::mt19937::result_type> dist6( 0,255 );

     for( int cnt = oneBlockSize; cnt > 0; cnt-- )
     {
          result.push_back( dist6( rng ) );
     }
     return result;
}


int AESCryptography::calculateNk( AesKeyLength len ) const
{
     switch( len )
     {
          case AKL_128:
          {
               return 4;
          }
          case AKL_192:
          {
               return 6;
          }
          case AKL_256:
          {
               return 8;
          }
     }
     return 0;
}


int AESCryptography::calculateNr( AesKeyLength len ) const
{
     switch( len )
     {
          case AKL_128:
          {
               return 10;
          }
          case AKL_192:
          {
               return 12;
          }
          case AKL_256:
          {
               return 14;
          }
     }
     return 0;
}


unsigned char AESCryptography::sboxValue( unsigned char src, const unsigned char sboxMatrix[16][16] )
{
     return sboxMatrix[ src / 16 ][ src % 16 ];
}


