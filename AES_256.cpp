#include "AES_256.h"

#include <stdexcept>
#include <cstring>
#include <iostream>
#include <random>

using namespace std;


vector< unsigned char > AES_256::crypt_data( const vector< unsigned char >& data, const std::vector< unsigned char >& key )
{
     if( data.size() % 16 != 0 )
     {
          throw runtime_error( "data is not aligned" );
     }

     unsigned char round_keys_matrix[ 4 ][ 60 ];
     KeyExpansion( key, round_keys_matrix );

     std::vector< unsigned char > result;
     for( int block = 0; block < data.size(); block+= 16 )
     {
          std::vector< unsigned char > tmp = crypt_block( { data.begin() + block, data.begin() + block + 16 }, round_keys_matrix );
          result.insert( result.end(), std::make_move_iterator( tmp.begin() ), std::make_move_iterator( tmp.end() ) );
     }
     return result;
}


std::vector<unsigned char> AES_256::crypt_data_cbc( const vector<unsigned char>& data, const vector<unsigned char>& key,
                                                    const vector<unsigned char>& iv )
{
     if( data.size() % 16 != 0 )
     {
          throw runtime_error( "data is not aligned" );
     }
     if( iv.size() != oneBlockSize )
     {
          throw runtime_error( "iv has not valid size" );
     }
     std::vector< unsigned char > last_encrypted_data = iv;
     unsigned char round_keys_matrix[ 4 ][ 60 ];
     KeyExpansion( key, round_keys_matrix );

     std::vector< unsigned char > result;
     for( int block = 0; block < data.size(); block+= 16 )
     {
          std::vector< unsigned char > src( data.begin() + block, data.begin() + block + 16 );
          src = vector_xor( src, last_encrypted_data );
          std::vector< unsigned char > tmp_result = crypt_block( src, round_keys_matrix );
          last_encrypted_data = tmp_result;
          result.insert( result.end(), std::make_move_iterator( tmp_result.begin() ), std::make_move_iterator( tmp_result.end() ) );
     }

     return result;
}


std::vector< unsigned char > AES_256::crypt_block( const vector< unsigned char >& data, unsigned char round_keys_matrix[ 4 ][ 60 ] )
{
     if( data.size() != 16 )
     {
          throw runtime_error( "invalid block size" );
     }
     unsigned char data_matrix[4][4];
     block_to_matrix_4x4( data, data_matrix );

     int round_key_idx = 0;
     addRoundKey( data_matrix, round_keys_matrix, round_key_idx );
     round_key_idx += 4;

     for( int round = 0; round < Nr - 1; round++ )
     {
          subBytes( data_matrix );
          shiftRows( data_matrix );
          mixColumn( data_matrix );
          addRoundKey( data_matrix, round_keys_matrix, round_key_idx );
          round_key_idx += 4;
     }

     subBytes( data_matrix );
     shiftRows( data_matrix );
     addRoundKey( data_matrix, round_keys_matrix, round_key_idx );


     return matrix_4_4_to_vector( data_matrix );
}


std::vector< unsigned char > AES_256::decrypt_data( const std::vector< unsigned char >& data, const std::vector< unsigned char >& key )
{
     if( data.size() % 16 != 0 )
     {
          throw runtime_error( "data is not aligned" );
     }

     unsigned char round_keys_matrix[ 4 ][ 60 ];
     KeyExpansion( key, round_keys_matrix );

     std::vector< unsigned char > result;
     for( int block = 0; block < data.size(); block+= 16 )
     {
          std::vector< unsigned char > tmp = decrypt_block( { data.begin() + block, data.begin() + block + 16 }, round_keys_matrix );
          result.insert( result.end(), std::make_move_iterator( tmp.begin() ), std::make_move_iterator( tmp.end() ) );
     }

     return result;
}

std::vector<unsigned char> AES_256::decrypt_data_cbc( const vector<unsigned char>& data, const vector<unsigned char>& key,
                                                      const vector<unsigned char>& iv )
{
     if( data.size() % 16 != 0 )
     {
          throw runtime_error( "data is not aligned" );
     }

     unsigned char round_keys_matrix[ 4 ][ 60 ];
     KeyExpansion( key, round_keys_matrix );

     std::vector< unsigned char > last_encrypted_data = iv;

     std::vector< unsigned char > result;
     for( int block = 0; block < data.size(); block+= 16 )
     {
          std::vector< unsigned char > src( data.begin() + block, data.begin() + block + 16 );
          std::vector< unsigned char > tmp = decrypt_block( src, round_keys_matrix );
          tmp = vector_xor( tmp, last_encrypted_data );
          last_encrypted_data = src;
          result.insert( result.end(), std::make_move_iterator( tmp.begin() ), std::make_move_iterator( tmp.end() ) );
     }

     return result;
}


std::vector< unsigned char > AES_256::decrypt_block( const std::vector< unsigned char >& data, unsigned char round_keys_matrix[ 4 ][ 60 ] )
{
     if( data.size() != 16 )
     {
          throw runtime_error( "invalid block size" );
     }
     unsigned char data_matrix[4][4];
     block_to_matrix_4x4( data, data_matrix );

     int roundKeyIdx = ( ( Nr + 1 ) ) * Nb - 4;

     addRoundKey( data_matrix, round_keys_matrix, roundKeyIdx );
     roundKeyIdx -= 4;

     for( int round = Nr - 1; round > 0; round-- )
     {
          invShiftRows( data_matrix );
          invSubBytes( data_matrix );
          addRoundKey( data_matrix, round_keys_matrix, roundKeyIdx );
          roundKeyIdx -= 4;
          invMixColumn( data_matrix );
     }

     invShiftRows( data_matrix );
     invSubBytes( data_matrix );
     addRoundKey( data_matrix, round_keys_matrix, roundKeyIdx );


     return matrix_4_4_to_vector( data_matrix );
}


void AES_256::block_to_matrix_4x4( const vector< unsigned char >& data, unsigned char data_matrix[ 4 ][ 4 ] )
{
     for( int idx = 0; idx < data.size(); idx++ )
     {
          data_matrix[ idx % 4 ][ idx / 4 ] = data[ idx ];
     }
}


void AES_256::subBytes( unsigned char data_matrix[4][4] )
{
     unsigned char* bytes = *data_matrix;
     for( int idx = 0; idx < 16; idx++ )
     {
          bytes[ idx ] = sbox[ bytes[ idx ] / 16 ][ bytes[ idx ] % 16 ];
     }
}


void AES_256::shiftRows( unsigned char data_matrix[4][4] )
{
     for( int row = 0; row < 4; row++ )
     {
          int shift_count = row;
          while( shift_count != 0 )
          {
               unsigned char first_byte = data_matrix[ row ][ 0 ];
               for( int idx = 1; idx < 4; idx++ )
               {
                    data_matrix[ row ][ idx - 1 ] = data_matrix[ row ][ idx ];
               }
               data_matrix[ row ][ 3 ] = first_byte;
               shift_count--;
          }
     }
}


void AES_256::mixColumn( unsigned char data_matrix[ 4 ][ 4 ] )
{
     for( int column = 0; column < 4; column++ )
     {
          unsigned char tmp_column[4];
          for( int row = 0; row < 4; row++ )
          {
               tmp_column[ row ] = multiplyBytes( mixColumnsMatrix[ row ][ 0 ],  data_matrix[ 0 ][ column ] ) ^
                                   multiplyBytes( mixColumnsMatrix[ row ][ 1 ],  data_matrix[ 1 ][ column ] ) ^
                                   multiplyBytes( mixColumnsMatrix[ row ][ 2 ],  data_matrix[ 2 ][ column ] ) ^
                                   multiplyBytes( mixColumnsMatrix[ row ][ 3 ],  data_matrix[ 3 ][ column ] );
          }

          for( int row = 0; row < 4; row++ )
          {
               data_matrix[ row ][ column ] = tmp_column[ row ];
          }
     }
}


unsigned char AES_256::multiplyBytes( unsigned char a, unsigned char b )
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


void AES_256::KeyExpansion( const vector< unsigned char >& key, unsigned char round_keys_matrix[ 4 ][ 60 ] )
{
     if( key.size() != Nk * 4 )
     {
          throw runtime_error( "invalid key size" );
     }

     memset( round_keys_matrix,0x0, 240 );

     for( int row = 0; row < 4; row++ )
     {
          for( int column = 0; column < Nk; column++ )
          {
               round_keys_matrix[ row ][ column ] = key[ row + 4 * column ];
          }
     }

     for( int column = Nk; column < 60; column++ )
     {
          if( column % Nk == 0 )
          {
               unsigned char tmp_column[ 4 ];
               shiftColumn( round_keys_matrix, column - 1, 1, tmp_column );

               for( int row = 0; row < 4; row++ )
               {
                    tmp_column[ row ] = sbox[ tmp_column[ row ] / 16 ][ tmp_column[ row ] % 16 ];
               }
               for( int row = 0; row < 4; row++ )
               {
                    round_keys_matrix[ row ][ column ] = round_keys_matrix[ row ][ column - Nk ] ^ tmp_column[ row ] ^
                            rcon( row, column / Nk - 1 );
               }
          }
          else if( Nk > 6 && column % Nk == 4 )
          {
               for( int row = 0; row < 4; row++ )
               {
                    round_keys_matrix[ row ][ column ] = round_keys_matrix[ row ][ column - Nk ] ^ sbox[ round_keys_matrix[ row ][ column - 1 ] / 16 ][ round_keys_matrix[ row ][ column - 1 ] % 16 ];
               }
          }
          else
          {
               for( int row = 0; row < 4; row++ )
               {
                    round_keys_matrix[ row ][ column ] = round_keys_matrix[ row ][ column - Nk ] ^ round_keys_matrix[ row ][ column - 1 ];
               }
          }
          //print_matrix( round_keys_matrix );
     }
     //print_matrix( round_keys_matrix );
}


void AES_256::shiftColumn( unsigned char round_keys_matrix[ 4 ][ 60 ], int column, int shift, unsigned char result[ 4 ] )
{
     for( int row = 0; row < 4; row++ )
     {
          result[ row ] = round_keys_matrix[ row ][ column ];
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


unsigned char AES_256::rcon( int row, int column )
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


void AES_256::addRoundKey(  unsigned char data_matrix[ 4 ][ 4 ], unsigned char round_keys_matrix[ 4 ][ 60 ], int first_column )
{
     for( int row = 0; row < 4; row++ )
     {
          for( int column = 0; column < 4; column++ )
          {
               data_matrix[ row ][ column ] ^= round_keys_matrix[ row ][ column + first_column ];
          }
     }
}


std::vector< unsigned char > AES_256::matrix_4_4_to_vector( unsigned char data_matrix[ 4 ][ 4 ] )
{
     std::vector< unsigned char > result;
     result.resize( 4 * Nb );
     for( int row = 0; row < 4; row++ )
     {
          for( int column = 0; column < Nb; column++ )
          {
               result[ row + 4 * column ] = data_matrix[ row ][ column ];
          }
     }
     return result;
}

void AES_256::print_matrix( unsigned char data_matrix[4][60] )
{
     for( int row = 0; row < 4; row++ )
     {
          for( int column = 0; column < 60; column++ )
          {
               std::cout << std::hex << "0x" << (int)data_matrix[ row ][ column ] << ' ';
          }
          std::cout << std::endl;
     }
     std::cout << std::endl;
}


void AES_256::invSubBytes( unsigned char data_matrix[ 4 ][ 4 ] )
{
     unsigned char* bytes = *data_matrix;
     for( int idx = 0; idx < 16; idx++ )
     {
          bytes[ idx ] = invSbox[ bytes[ idx ] / 16 ][ bytes[ idx ] % 16 ];
     }
}


void AES_256::invShiftRows( unsigned char data_matrix[ 4 ][ 4 ] )
{
     for( int row = 0; row < 4; row++ )
     {
          int shift_count = row;
          while( shift_count != 0 )
          {
               unsigned char first_byte = data_matrix[ row ][ 3 ];
               for( int idx = 3; idx > 0; idx-- )
               {
                    data_matrix[ row ][ idx ] = data_matrix[ row ][ idx - 1 ];
               }
               data_matrix[ row ][ 0 ] = first_byte;
               shift_count--;
          }
     }
}


void AES_256::invMixColumn( unsigned char data_matrix[ 4 ][ 4 ] )
{
     for( int column = 0; column < 4; column++ )
     {
          unsigned char tmp_column[4];
          for( int row = 0; row < 4; row++ )
          {
               tmp_column[ row ] = multiplyBytes( invMixColumnsMatrix[ row ][ 0 ],  data_matrix[ 0 ][ column ] ) ^
                                   multiplyBytes( invMixColumnsMatrix[ row ][ 1 ],  data_matrix[ 1 ][ column ] ) ^
                                   multiplyBytes( invMixColumnsMatrix[ row ][ 2 ],  data_matrix[ 2 ][ column ] ) ^
                                   multiplyBytes( invMixColumnsMatrix[ row ][ 3 ],  data_matrix[ 3 ][ column ] );
          }

          for( int row = 0; row < 4; row++ )
          {
               data_matrix[ row ][ column ] = tmp_column[ row ];
          }
     }
}

std::vector< unsigned char > AES_256::vector_xor( const vector<unsigned char>& lhs, const vector<unsigned char>& rhs )
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


std::vector<unsigned char> AES_256::create_iv()
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


