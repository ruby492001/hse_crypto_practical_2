#include <iostream>
#include <cstring>
#include "file_crypt.h"


void printHelp()
{
     std::cout << "Usage: {encrypt/decrypt} {CBC/ECB} {KEY in HEX format} {Source file path} {Destination file path} {OPTIONAL: IV in HEX format}" << std::endl;
     std::cout << "Examples:\n"
                    "\tencrypt CBC 88CF1B7478A797F03F54527B50EF6D427B8F8C9C4EFB7FC20AA06B0DCD94FD35 file_to_crypt.txt encrypted_file.txt 88CF1B7478A797F03F54527B50EF6D41\n"
                    "\tdecrypt CBC 88CF1B7478A797F03F54527B50EF6D427B8F8C9C4EFB7FC20AA06B0DCD94FD35 encrypted_file.txt decrypted_file.txt 88CF1B7478A797F03F54527B50EF6D41" << std::endl;
}


void exec( const std::vector< std::string >& args )
{
     bool decrypt = false;
     bool cbc = false;
     std::vector< unsigned char > key = FileEncryptor::hexToArray( args[ 2 ] );
     std::string inputFile = args[ 3 ];
     std::string outputFile = args[ 4 ];
     std::vector< unsigned char > iv;
     if( args[ 0 ] == "decrypt" )
     {
          decrypt = true;
     }
     else if( args[ 0 ] != "encrypt" )
     {
          throw std::runtime_error( "incorrect action: " + args[ 0 ] );
     }

     if( args[ 1 ] == "CBC" )
     {
          cbc = true;
     }
     else if( args[ 1 ] != "ECB" )
     {
          throw std::runtime_error( "incorrect encrypt mode: " + args[ 1 ] );
     }

     if( args.size() >= 6 )
     {
          iv = FileEncryptor::hexToArray( args[ 5 ] );
     }

     FileEncryptor fileCrypt( inputFile, outputFile );

     if( decrypt )
     {
          fileCrypt.decryptFile( key, cbc ? CMCbc : CMEcb, iv );
     }
     else
     {
          fileCrypt.cryptFile( key, cbc ? CMCbc : CMEcb, iv );
     }
}


int main( int argc, char* argv[] )
{
     if( argc < 6 || ( strlen( argv[ 1 ] ) == 0 && argv[ 1 ][ 0 ] == 'h' ) )
     {
          printHelp();
          return 0;
     }

     std::vector< std::string > args;
     for( int idx = 1; idx < argc; idx++ )
     {
          args.emplace_back( argv[ idx ] );
     }

     try
     {
          exec( args );
     }
     catch ( const std::exception& ex )
     {
          std::cout << ex.what() << std::endl;
          return -1;
     }

     return 0;
}
