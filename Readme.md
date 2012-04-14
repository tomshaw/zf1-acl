# Zend ACL (A)ccess (C)ontrol (L)ist Implementation
      
  The Zend Access Control object is a simple implementation of Zend_Acl. It provides the perfect starting point to develop your applications ACL dripping with Kool-Aid.
    
## Installation

  Enable the plugin via your Zend Framework projects application.ini
  
    resources.frontController.plugins.acl = App_Controller_Plugin_Acl
    
  Also make sure the base autoloader namespace is registered.
  
    autoloaderNamespaces[] = "App"

# API 

There are some additional public methods that I have found useful. These methods are documented in the doc blocks and are somewhat self explanatory.

# Questions or Comments?

Email: tom@tomshaw.info

## License 

(The MIT License)

Copyright (c) 2011 Tom Shaw &lt;tom@tomshaw.info&gt;

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
'Software'), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.