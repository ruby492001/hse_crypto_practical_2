#include "file_crypt.h"
#include <fstream>
#include <exception>



FileEncryptor::FileEncryptor( const std::string& srcPath, const std::string& dstPath )
:srcPath_( srcPath ), dstPath_( dstPath )
{
}


void FileEncryptor::cryptFile( const std::vector< unsigned char >& key, CryptMode mode )
{
     AesKeyLength keyLength = keyLengthFromKey( key );

     std::ifstream inp( srcPath_, std::ios_base::binary | std::ios_base::in );
     if( !inp.is_open() )
     {
          throw std::runtime_error( "Input file does not not exist or unavailable" );
     }

     std::ofstream out( dstPath_, std::ios_base::binary | std::ios_base::out );
     if( !out.is_open() )
     {
          throw std::runtime_error( "Create output file error" );
     }

     std::vector< unsigned char > data;

     // выполняем чтение из файла
     const int tmpSize = 1024;
     std::vector< unsigned char > tmpArr( tmpSize );
     while( inp.good() )
     {
          std::streamsize readBytes = inp.read( ( char* ) tmpArr.data(), tmpSize ).gcount();
          if( readBytes != 0 )
          {
               data.insert( data.end(), tmpArr.begin(), tmpArr.begin() + readBytes );
          }
     }

     // выполняем дополнение
     addPadding( data );

     // выполняем шифрование
     std::vector< unsigned char > encryptedData;
     AESCryptography crypt( keyLength );
     std::vector< unsigned char > iv;
     if( mode == CMCbc )
     {
          iv = crypt.create_iv();
          encryptedData = crypt.cryptDataCBC( data, key, iv );
     }
     else
     {
          encryptedData = crypt.cryptDataECB( data, key );
     }

     // выполняем запись файл в формате: IV + шифртекст. Если IV нет - только шифртекст
     if( !iv.empty() )
     {
          out.write( ( char* ) iv.data(), iv.size() );
     }

     out.write( ( char* ) encryptedData.data(), encryptedData.size() );
}


void FileEncryptor::decryptFile( const std::vector<unsigned char>& key, CryptMode mode )
{
     AesKeyLength keyLength = keyLengthFromKey( key );

     std::ifstream inp( srcPath_, std::ios_base::binary | std::ios_base::in );
     if( !inp.is_open() )
     {
          throw std::runtime_error( "Input file does not not exist or unavailable" );
     }

     std::ofstream out( dstPath_, std::ios_base::binary | std::ios_base::out );
     if( !out.is_open() )
     {
          throw std::runtime_error( "Create output file error" );
     }

     std::vector< unsigned char > data;

     // выполняем чтение шифртекста из файла
     const int tmpSize = 1024;
     std::vector< unsigned char > tmpArr( tmpSize );
     while( inp.good() )
     {
          std::streamsize readBytes = inp.read( ( char* ) tmpArr.data(), tmpSize ).gcount();
          if( readBytes != 0 )
          {
               data.insert( data.end(), tmpArr.begin(), tmpArr.begin() + readBytes );
          }
     }

     // если алгоритм шифрования подразумевает наличие IV - считываем его из полученного массива
     std::vector< unsigned char > iv;
     if( mode == CMCbc )
     {
          iv = extractIv( data );
     }

     // выполняем расшифрование
     std::vector< unsigned char > decryptedData;
     AESCryptography crypt( keyLength );
     if( mode == CMCbc )
     {
          decryptedData = crypt.decryptDataCBC( data, key, iv );
     }
     else
     {
          decryptedData = crypt.decryptDataECB( data, key );
     }

     // удаляем дополнение
     removePadding( decryptedData );

     // выполняем запись открытого текста в указанный файл
     out.write( ( char* ) decryptedData.data(), decryptedData.size() );
}


std::vector< unsigned char > FileEncryptor::extractIv( std::vector< unsigned char >& data )
{
     int ivSize = 16;
     if( data.size() < ivSize )
     {
          throw std::runtime_error( "Input file corrupted" );
     }
     std::vector< unsigned char > iv( data.begin(), data.begin() + ivSize );
     data.erase( data.begin(), data.begin() + ivSize );
     return iv;
}


void FileEncryptor::addPadding( std::vector<unsigned char>& data )
{
     int paddingSize = 16 - ( data.size() % 16 );

     std::vector< unsigned char > padding( paddingSize, paddingSize );
     data.insert( data.end(), padding.begin(), padding.end() );
}


void FileEncryptor::removePadding( std::vector<unsigned char>& data )
{
     if( data.empty() )
     {
          throw std::runtime_error( "Input file corrupted" );
     }
     int paddingSize = *data.rbegin();
     if( data.size() < paddingSize )
     {
          throw std::runtime_error( "Input file corrupted" );
     }
     for( int cnt = paddingSize; cnt > 0; cnt-- )
     {
          if( *data.rbegin() != paddingSize )
          {
               throw std::runtime_error( "Input file corrupted" );
          }
          data.pop_back();
     }
}


AesKeyLength FileEncryptor::keyLengthFromKey( const std::vector< unsigned char >& key )
{
     switch( key.size() * 8 )
     {
          case 128:
          {
               return AKL_128;
          }
          case 192:
          {
               return AKL_192;
          }
          case 256:
          {
               return AKL_256;
          }
     }
     throw std::runtime_error( "Incorrect key length" );
}


std::vector< unsigned char > FileEncryptor::hexToArray( const std::string& str )
{
     if( str.size() % 2 != 0 )
     {
          throw std::runtime_error( "Incorrect HEX value" );
     }
     std::vector< unsigned char > result;

     for(int idx = 0; idx < str.size(); idx += 2)
     {
          result.push_back(static_cast<unsigned char>(std::stoi(str.substr(idx, 2), nullptr, 16)));
     }

     return result;
}
