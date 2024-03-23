#include "AES_cryptography.h"
#include <vector>
#include <string>


enum CryptMode
{
     CMCbc,
     CMEcb
};

class FileEncryptor
{
public:
     FileEncryptor( const std::string& srcPath, const std::string& dstPath );
     void cryptFile( const std::vector< unsigned char >& key, CryptMode mode );
     void decryptFile( const std::vector< unsigned char >& key, CryptMode mode );

     static std::vector< unsigned char > hexToArray( const std::string& str );
private:
     // методы создания и удаления дополнения по методу PKCS
     void addPadding( std::vector< unsigned char >& data );
     void removePadding( std::vector< unsigned char >& data );

     // расчитывает длину ключа шифрования/расшифрования из ключа
     AesKeyLength keyLengthFromKey( const std::vector< unsigned char >& key );

     // извлекает IV из массива и возвращает его
     std::vector< unsigned char >  extractIv( std::vector< unsigned char >& data );

private:
     const std::string srcPath_;
     const std::string dstPath_;
};



