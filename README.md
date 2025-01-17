# vhx encryption algorithm  

vhx (vector hash expansion encryption) is my first encryption algorithm.  
it is simple to use and designed to be lightweight while still providing security.  
vhx does not rely on openssl and can encrypt any type of data, including text, files, and binary streams.  

## features  
- does not require external libraries  
- uses dynamic block size and modular transformations  
- works on windows, linux, and macos  
- simple and easy to use  

## how it works  
vhx applies mathematical transformations and xor operations to obfuscate data. it generates a 256-bit encryption key, processes data in variable-length blocks, and applies a unique transformation formula to strengthen security.  
