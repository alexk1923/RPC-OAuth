[![LinkedIn][linkedin-shield]][linkedin-url]
[![github][github-shield]][github-url]

<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/alexk1923/RPC-OAuth/blob/main/src/img/rpc-client-server-auth.png">
    <img src="images/logo.png" alt="Logo" width="80" height="80">
  </a>

  <h3 align="center">Client-Server OAuth App using RPC Protocol</h3>

  <p align="center">
    <a href="https://github.com/alexk1923/RPC-OAuth/blob/main/SPRC_2023_2024___Tema_1.pdf"><strong>Explore the docs »</strong></a>
</p>

<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>

<!-- ABOUT THE PROJECT -->

## About The Project

[![RPC-OAuth-Client-Server][product-screenshot]](https://github.com/alexk1923/RPC-OAuth/blob/main/src/img/schema_logica.png)

The app is using RPC Concept to simulate an authorization system using OAuth. It is working by a request-response system between the server and the client, authorizing RIMDX (Read, Insert, Modify, Delete, Execute) actions type to simulate the access to some resources stored on the server.

**Description of the two entities:**

1. Client: a third party app that is used by the end-user to access resources. It is responsible to authorize actions performed by the end-user
2. Server: providing tokens, access to resources and approval component for the user

**Example**
A student is using a third party app (LaTeX Editor) to access and edit some documents stored on the university cloud. He does not want to expose his credentials to the editor app, so the OAuth standard will be used in order to give management permission for the document editor. An access token will be used further to allow client to edit and save documents on the cloud.

<p align="right">(<a href="#readme-top">back to top</a>)</p>

### Built With

[![Cpp][Cpp]][Cpp-url]
[![rpc][rpc]][rpc-url]

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- GETTING STARTED -->

## Getting Started

This is an example of how you may give instructions on setting up your project locally.
To get a local copy up and running follow these simple example steps.

### Prerequisites

This is an example of how to list things you need to use the software and how to install them.

- rpcbind
  ```sh
  sudo apt-get install rpcbind
  sudo /etc/init.d/rpcbind start
  ```
- run `rpcinfo -p` to check if the RPC server is running
- Make sure `g++` compiler is installed
  ```sh
   sudo apt-get install g++
  ```

### Installation

_Below is an example of how you can instruct your audience on installing and setting up your app. This template doesn't rely on any external dependencies or services._

1. Clone the repo

   ```sh
   git clone git@github.com:alexk1923/RPC-OAuth.git
   ```

2. Edit the configuration in check.sh by completing SERVER and CLIENT params
   ```sh
   SERVER_NAME="src/server"
   CLIENT_NAME="src/client"
   SERVER_ADDR="localhost" (OR another valid address)
   ```
3. Run Makefile (from src directory)
   ```sh
   make
   ```
4. Run the checker to see the result
   ```sh
   ./check.sh testNo([0-7]|all) [showOutput([0-1])]
   ```
   <p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- USAGE EXAMPLES -->

## Implementation

**Server**:

- _oauth_svc.c_ - (stub generated by rpc)
  - The program starts by parsing the input files given as command line args to populate the server database with the list of users, resources and resource permissions.
- _oauth_server.cpp_ - **Authorization**: the user id is passed to the function. If the user id is valid, then an authorization token is generated and returned. Otherwise, USER_NOT_FOUND error code is returned - **Approve Permissions**: this is the functionality that the server needs to implement to associate the authorization token with a set of permissions approved by the end-user. The token is modified by adding a ".SIGNED" suffix, also being marked as SIGNED in the server database - **Access**: The authorization token is provided to generate an access token to the resources. If the auto-refresh option is set, then a refresh token is also generated. After creation, the lifespan of the token is set based on command line argument passed to the server - **Refresh**: It is using an existing access token to get another access and refresh token. Also, the number of requests to be made is reset to the default lifespan

**Client**

- oauth_client.cpp - The client starts by parsing commands and process each line. An operation structure is used to store information about the user action (User Id, Operation Type, Resource and Automatic Refresh Option) - The information about each user and his access token is stored in clientsTokens map

**Data Structures**

Based on the fact that multiple data is processed and stored in the client and server variables, the choice was to use maps to improve performance by quick access to the desired pair.

- For the client, pairs of clients ids and tokens are required.
- For the server vectors are used to store input data, the tokens being coupled in maps with approval status, resource accessing permissions or existing users id. Maps were used to ensure the uniqueness of the data, as each user has its own unique token at a time.

Operations and status codes enums were used to define the base values and improve scalability for future development, alongside with const array vectors using constant to "convert" enums to string values.

**Helpers**

Constants & Utils

- The utilization of constants within the project contributes to an elevated level of code readability. Descriptively named constants offer a transparent and self-explanatory context for the values they embody.

\_For more examples, please refer to the [Documentation](https://github.com/alexk1923/RPC-OAuth/blob/main/SPRC_2023_2024___Tema_1.pdf)\_

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- CONTACT -->

## Contact

LinkedIn: [alexandru-kullman](https://www.linkedin.com/in/alexandru-kullman/)

Github: [alexk1923](https://github.com/alexk1923)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- ACKNOWLEDGMENTS -->

## ACKNOWLEDGMENTS

Use this space to list resources you find helpful and would like to give credit to. I've included a few of my favorites to kick things off!

- [SPRC - Lab 2 Resources]()
- [rpcgen - man](https://linux.die.net/man/1/rpcgen)
- [CPP - Function Docs](https://developer.lsst.io/cpp/api-docs.html)

<p align="right">(<a href="#readme-top">back to top</a>)</p>

<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->

[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://linkedin.com/in/othneildrew
[product-screenshot]: images/screenshot.png
[Cpp]: https://img.shields.io/badge/c++-%2300599C.svg?style=for-the-badge&logo=c%2B%2B&logoColor=white
[Cpp-url]: https://devdocs.io/c/
[rpc]: https://img.shields.io/badge/RPC-00599C
[rpc-url]: https://www.ibm.com/docs/en/aix/7.1?topic=concepts-remote-procedure-call
[github-shield]: https://img.shields.io/badge/github-%23121011.svg?style=for-the-badge&logo=github&logoColor=white
[github-url]: https://github.com/alexk1923