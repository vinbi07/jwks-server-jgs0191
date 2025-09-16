# JWKS Server (Node + Express + jose)

Project for CSCE 3550 

## Authors

- jsg0191 (JoeyRyanSuliguin@my.unt.edu)

## Installation

To install, run the following command

```bash
   npm install
```

## Running The Server

To run the server, run the following command

```bash
   npm start
```


## Running Tests

To run tests, run the following command

```bash
   npx jest --coverage
```
```bash
  ./gradebot project1
```

## Use of AI
To create this JWKS server, I used a series of AI prompts that guided step-by-step development using JavaScript based on the assignment guidelines. These prompts included requests to write a keystore with in-memory RSA key pairs, support for kid headers, and automatic handling of key expiration. I also asked for Express route implementations for /auth and /jwks, with correct HTTP status codes for valid and invalid requests. Additional prompts focused on writing comprehensive Jest tests, including edge cases for expired tokens, missing payload fields, and invalid signing parameters, as well as ensuring branch coverage and ensuring all tests pass. I also prompted the AI to help refactor code for clarity and maintainability, and implement proper token expiration handling.
