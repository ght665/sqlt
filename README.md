# sqlt: A Go Template-Based SQL Builder and Struct Mapper

![sqlt](https://img.shields.io/badge/sqlt-v1.0.0-brightgreen.svg) ![Go](https://img.shields.io/badge/Go-1.16%2B-blue.svg) ![License](https://img.shields.io/badge/license-MIT-lightgrey.svg)

Welcome to the **sqlt** repository! This project is a Go library designed to simplify SQL query building and struct mapping. With **sqlt**, you can create SQL queries in a type-safe manner while maintaining the flexibility of templates. This README will guide you through the features, installation, usage, and more.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)
- [Releases](#releases)

## Features

- **Template-Based**: Utilize Go templates to construct SQL queries.
- **Type-Safe**: Enjoy compile-time checks for SQL queries.
- **Multi-Database Support**: Works with MySQL, PostgreSQL, SQLite, and more.
- **No ORM Required**: Directly map structs to SQL without the overhead of an ORM.
- **Flexible**: Easily modify queries using templates.

## Installation

To install **sqlt**, you can use the following command:

```bash
go get github.com/ght665/sqlt
```

Make sure you have Go installed on your machine. If you need help with installation, refer to the [Go installation guide](https://golang.org/doc/install).

## Usage

To get started with **sqlt**, follow these simple steps:

1. **Import the package**:

   ```go
   import "github.com/ght665/sqlt"
   ```

2. **Create a new SQL builder**:

   ```go
   builder := sqlt.NewBuilder()
   ```

3. **Build your SQL query**:

   ```go
   query := builder.Select("*").From("users").Where("id = ?", userID).Build()
   ```

4. **Execute the query**:

   Use your preferred database driver to execute the query.

## Examples

Here are a few examples to demonstrate how to use **sqlt** effectively.

### Example 1: Simple Select Query

```go
package main

import (
    "fmt"
    "github.com/ght665/sqlt"
)

func main() {
    builder := sqlt.NewBuilder()
    query := builder.Select("name, email").From("users").Where("active = true").Build()
    fmt.Println(query)
}
```

### Example 2: Insert Query with Struct Mapping

```go
package main

import (
    "github.com/ght665/sqlt"
)

type User struct {
    Name  string
    Email string
}

func main() {
    user := User{Name: "John Doe", Email: "john@example.com"}
    builder := sqlt.NewBuilder()
    query := builder.InsertInto("users").Values(user).Build()
    fmt.Println(query)
}
```

### Example 3: Using Templates

```go
package main

import (
    "github.com/ght665/sqlt"
)

func main() {
    template := "SELECT {{.Fields}} FROM {{.Table}} WHERE {{.Condition}}"
    data := map[string]interface{}{
        "Fields": "name, email",
        "Table":  "users",
        "Condition": "active = true",
    }
    
    builder := sqlt.NewBuilder()
    query := builder.Template(template, data).Build()
    fmt.Println(query)
}
```

## Contributing

We welcome contributions! If you want to help improve **sqlt**, please follow these steps:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes and commit them.
4. Push your branch and create a pull request.

Please ensure that your code follows the project's style and includes tests where applicable.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Releases

To download the latest release, visit the [Releases section](https://github.com/ght665/sqlt/releases). You can find the files you need to download and execute there.

For the latest updates and changes, keep an eye on the releases page. 

## Conclusion

**sqlt** provides a straightforward way to build SQL queries in Go. Its template-based approach allows for flexibility while ensuring type safety. Whether you are working with MySQL, PostgreSQL, or SQLite, **sqlt** can help streamline your database interactions.

If you have any questions or need further assistance, feel free to open an issue in the repository. We appreciate your interest in **sqlt** and look forward to your contributions!