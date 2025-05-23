# Slices

<show-structure depth="2"/>

> This feature is still work in progress.
> {style="note"}

The Changes and Query APIs are expressive ways to interact with the Knowledge Graph of a Pod. However, they provide
access to the entire Knowledge Graph, which may not always be necessary or desirable. In some cases, it may be more
efficient to work with a well-defined subset of the Knowledge Graph, known as a "slice". Also from the perspective of
access control, it is easier to manage coarse-grained permissions on such a slice, compared to fine-grained permissions
on the entire Knowledge Graph.

In a way, a slice is similar to a view in a relational database, where only a subset of the data is exposed to the user.
Slices can be used to filter the data based on certain criteria, such as a specific type of resource, a particular
property, a specific value range, etc. However, unlike views, slices are not restricted to read-only access; they can
also be used for write operations (e.g. restricting the data that can be inserted for a specific slice to a certain
shape).

## Defining a Slice

A slice is defined by a set of criteria that determine which resources are included in the slice. These criteria can be
specified using a GraphQL schema, annotated with Kvasir directives to fully qualify the graph elements, or to express
additional constraints.

For example, the following schema defines a read-only slice that includes only resources of type `Person` and restricts
the visible properties to `givenName`, `familyName` and `email`:

```graphql
type Query {
    persons: [Person!]!
}

type Person @class(iri: "http://schema.org/Person") {
    id: ID!
    givenName: String! @predicate(iri: "http://schema.org/givenName")
    familyName: String! @predicate(iri: "http://schema.org/familyName")
    email: [String!] @predicate(iri: "http://schema.org/email")
}
```

By also supplying a JSON-LD context for the Slice definition, the schema can be simplified through prefixes (see
also: [Querying - Namespace prefixes](Querying.md#namespace-prefixes)).

**JSON-LD context**

```json
{
  "schema": "http://schema.org/"
}
```

**Simplified schema**

```graphql
type Query {
    persons: [schema_Person!]!
}

type schema_Person {
    id: ID!
    schema_givenName: String!
    schema_familyName: String!
    schema_email: [String!]
}
```

### Data restrictions

To further restrict the data retrievable via the Slice, use the [`@filter` directive](Querying.md#filters) similarly to
how you would narrow down results for a Query. The filters associated with the Slice schema are combined with those in
the query document when Kvasir executes a GraphQL query. This ensures that the Slice interfaces cannot expose data
beyond the reach of its defined subgraph.

For example, the following schema defines a slice that includes only resources of type `Person`, which have at least one
email address, ending on `@example.com`:

```graphql
type Query {
    persons: [schema_Person!]!
}

type schema_Person {
    id: ID!
    schema_givenName: String!
    schema_familyName: String!
    schema_email: [String!] @filter(if: "it==*@example.org")
}
```

### Describing mutations

A Slice can specify mutations (insertions, deletions) that can be applied using the
standard [GraphQL Mutation Type and input types](https://graphql.org/learn/mutations/). However, there are a couple of
restrictions in place (in order to make sure Kvasir can interpret and execute these mutations on top of the Knowledge
Graph):

* Mutations names must start with a `insert`, `add`, `delete` or `remove` prefix, indicating the intent of the Mutation.
* Arguments for the mutation must be an Input Type or an array of an Input Type, annotated with the `@class` directive,
  so it is fully semantically qualified.
* The mutation must have `ID` as return type. The return value will be the URI of the [Change Request](Changes.md) that
  results from the mutation.

We chose to having to explicitly model the mutations, instead of automatically deriving possible mutations from the
Query schema. This allows the Slice author to have full control of what data is readable vs. what data can be changed.

As a result, mutations on a Slice can be executed in two ways:

1. Via the Slice-specific Changes API at `/{podId}/slices/{sliceId}/changes`.
2. Via the Slice-specific GraphQL interface at `/{podId}/slices/{sliceId}/query`, using the defined Mutation Type.

For example: the following GraphQL document, defines mutations for adding or removing Person information (with context
entry `"schema": "http://schema.org/"`):

```graphql
type Mutation {
  add(person: [PersonInput!]!): ID!
  remove(person: [PersonInput!]!): ID!
}

input PersonInput @class(iri: "schema:Person") {
  id: ID!
  schema_givenName: String!
  schema_familyName: String!
  schema_email: [String!]
}
```

This example allows clients with write-access to the Slice, to add or remove Persons, which must a `givenName`,
`familyName` and zero or multiple email addresses.

### Input type constraints

Just like the `@filter` directive can be used to limit the view-aspect of a Slice, Kvasir supports modeling constraints
for the possible mutation input data via the `@shape` directive. This directive is inspired
by [SHACL](https://www.w3.org/TR/shacl/).

The `@shape` directive supports the following arguments:

| Argument     | GraphQL Type | Description                                                                                             |
|--------------|--------------|---------------------------------------------------------------------------------------------------------|
| minExclusive | String       | All values must be greater than the provided String representation of the reference value.              |
| minInclusive | String       | All values must be greater than or equal to the provided String representation of the reference value.  |
| maxExclusive | String       | All values must be less than the provided String representation of the reference value.                 |
| maxInclusive | String       | All values must be less than or equal to the provided String representation of the reference value.     |
| minLength    | Int          | To be used with String properties. The input String value should be at least of the provided length.    |
| maxLength    | Int          | To be used with String properties. The input String value should be no longer than the provided length. | 
| pattern      | String       | To be used with String properties. The input String value should match the provided regex.              |
| flags        | String       | Use in combination with `pattern` to provide flags, such as `i` to ignore case.                         |
| hasValue     | String       | The input value must be equal to the provided value (as String representation).                         |
| in           | [String]     | The input value must be a member of the provided list of value String representations.                  |

For example: we could add a constraint to the previous example, expressing that only Persons with the `familyName`
`"Doe"`
can be inserted or deleted from the Slice, and that the `firstName` must contain at least two characters:

```graphql
type Mutation {
  add(person: [PersonInput!]!): ID!
  remove(person: [PersonInput!]!): ID!
}

input PersonInput @class(iri: "schema:Person") {
  id: ID!
  schema_givenName: String! @shape(minLength: 2)
  schema_familyName: String! @shape(hasValue: "Doe")
  schema_email: [String!]
}
```

### Registering the definition

To register the Slice, post the definition to the `/slices` endpoint of the Pod:

**POST** `http://localhost:8080/alice/slices`

```json
{
  "@context": {
    "kss": "https://kvasir.discover.ilabt.imec.be/vocab#",
    "schema": "http://schema.org/"
  },
  "kss:name": "PersonDemoSlice",
  "kss:description": "Demo Slice exposing Persons that have an '@example.org' email address",
  "kss:schema": "type Query { persons: [schema_Person!]! } type schema_Person { id: ID! schema_givenName: String! schema_familyName: String! schema_email: [String!]! @shape(pattern: \".*@example\\\\.org$\") }"
}
```

If the Slice is registered successfully, the operation will return a `201 Created` status code and the response headers
will include a `Location` header with the URL of the newly created Slice.

## Inspecting a Slice

You can inspect the definition of a Slice by sending a `GET` request to the URL of the Slice:

**GET** `http://localhost:8080/alice/slices/PersonDemoSlice`

The response will include the Slice definition in the body of the response.

## Using a Slice

Once a Slice is registered, operations that are available for the Knowledge Graph can also be performed on the
Slice. The base URL for the API operations on a Slice is the URL of the Slice (e.g.
`http://localhost:8080/alice/slices/PersonDemoSlice/`) compared to the base URL of the pod (e.g.
`http://localhost:8080/alice`) when performing Knowledge Graph global operations.

### Retrieving Slice data

Querying a Slice is similar to [querying the entire Knowledge Graph](Querying.md), but the query is restricted by the
pre-defined schema, instead of relying on an auto-generated schema for the entire Knowledge Graph.

For example, to retrieve all persons from the `PersonDemoSlice`, you can send a `POST` request to the `query` endpoint:

**POST** `http://localhost:8080/alice/slices/PersonDemoSlice/query`

```json
{
  "query": "{ persons { id schema_givenName schema_familyName schema_email } }"
}
```

### Mutations on a Slice

When enabled, a Slice can also expose a Changes API, allowing mutations on the Slice. The mutations are restricted by
the pre-defined schema, ensuring that only resources that match the criteria of the Slice can be created, updated or
deleted.

Additionally, if the Slice defines a Mutation Type, mutations may be performed directly using the GraphQL interface (in
addition to performing mutations via the Changes API).

For example, to add a Person, you can send a `POST` request to the `query` endpoint:

```json
{
  "query": "mutation { add(person: { id: \"ex:jdoe\" schema_givenName: \"John\" schema_familyName: \"Doe\" }) }"
}
```

