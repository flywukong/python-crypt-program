//通过python import hook机制实现对pyc文件的加密　加密后的文件不能被反编译

使用工具之前需要安装Cython和pycrypto包

将需要加密的pyc文件全部加入到app文件夹中
执行make 则文件夹中所有文件都会被加密　并且会生成ihook.so

主模块__main__.py中，第一句添加语句import ihook;ihook.install_hook注册钩子，注册之后主模块就能够正常加载加密后的pyc文件
