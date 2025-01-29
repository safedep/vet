# Storage

`vet` contains a storage engine defined in `pkg/storage`. We use `sqlite3` as
the database and [ent](https://entgo.io/) as the ORM.

## Usage

- Create new schema using the following command

```shell
go run -mod=mod entgo.io/ent/cmd/ent new CodeSourceFile
```

- Schemas are generated in `./ent/schema` directory
- Edit the generated schema file and add the necessary fields and edges
- Generate the models from the schema using the following command

```shell
make ent
```

- Make sure to commit any changes to `ent` directory including the generated
    files

## Guidance

All schemas are stored in `./ent/schema` directory. To avoid naming conflicts,
prefer prefixing the schema name with the logical module name. Example: `CodeSourceFile` is
used as the schema for storing `SourceFile` within `Code` analysis module.
