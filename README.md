# BryChallenge

## Requirements
- g++ 9.4.0+
- cmake 3.16.3+
- conan 2.16.1+

## Build and run
Create a folder to build files:
```bash
mkdir build
```

Install dependencies:
```bash
conan install -s compiler.cppstd=gnu17 -of=build --build=missing .
```

Enter build folder and generate cmake files:
```bash
cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_TOOLCHAIN_FILE=build/conan_toolchain.cmake
```

Build:
```bash
make
```

Run the API:
```bash
./app
```

Run the tests:
```bash
ctest
```
## API Requests

To sign a file:
```bash
curl 'localhost:8080/signature/' \
--form 'password="your_password";type=multipart/form-data' \
--form 'filename=@"/path/to/file/file_to_sign.txt"' \
--form 'cert=@"/path/to/certifcate/pkcs12/cert.pfx"'
```
