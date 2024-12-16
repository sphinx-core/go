# Introduction

Sphinx is a blockchain layer 1 technology designed to be a highly secure blockchain that incorporates post-quantum cryptographic algorithms. Our interemediate goals is to ensure blockchain security remains robust in the face of emerging threats posed by quantum computing.

We encourage developers, researchers, and blockchain enthusiasts to contribute to our project and participate in discussions to enhance the protocol.

## What is SPHINX?

Sphinx is an open-source, post-quantum secure blockchain layer 1 protocol written in Go. We believe that every person brings a unique perspective and set of skills, which is why everyone is invited to contribute to this project. Whether you're a developer, researcher, or enthusiast, your input can help us build a resilient, future-proof blockchain infrastructure resistant to quantum attacks. The project is under active development, and we welcome contributions from all walks of life!

## Getting Started

To contribute to the project, you need to have Go installed on your system. Follow the steps below to set up your environment.

### 1. Install Go
You can install Go by following the official instructions on the **[Go Installation page](https://go.dev/doc/install)**.

**For Linux/macOS:**

```bash 
wget https://go.dev/dl/go1.XX.X.linux-amd64.tar.gz
```

```bash
sudo tar -C /usr/local -xzf go1.XX.X.linux-amd64.tar.gz
```

```bash
export PATH=$PATH:/usr/local/go/bin
```


For Windows, download the installer from here **[Go Installation page](https://go.dev/doc/install)**.

**Verify your Go installation:**

```bash
go version
```

### 2. Clone the Repository
Once Go is set up, clone the repository to your local machine.

```bash
git clone https://github.com/sphinx-core/sphinx-core.git
```

```bash
cd sphinx-core
```

### 3. Fork the Repository
If you intend to contribute, it is recommended to fork the repository. You can do this by clicking the "Fork" button in the upper-right corner of the repository page.

### 4. Set Up Your Fork
Add your fork as a remote:

```bash
git remote add fork https://github.com/<your-username>/sphinx-core.git
```

## Contribution Guidelines

We encourage the community to help improve Sphinx-Core. You can contribute in many ways: 
1. fixing bugs
2. writing documentation
3. implementing new features
4. or suggesting new ideas.

###  Clone and Fork the Repository
Make sure your local repository is up to date:

```bash
git pull origin main
```

### Making Changes
1. Create a new branch for your feature or bug fix:

```bash
git checkout -b feature-name
```

2. Make the necessary changes in the code. Ensure your code is clean and well-documented.
3. Test your code locally.


### Submitting a Pull Request
1. Push your branch to your forked repository:

```bash
git push fork feature-name
```

2. Create a pull request (PR) to the main repository from your branch on GitHub. Make sure your PR description clearly explains your changes.
3. Wait for the review process. Be prepared to receive feedback or requests for changes.

Proposals and Discussions

All major proposals for features, upgrades, and changes are documented in the **[GitHub Wiki](https://github.com/sphinx-core/sips/wiki).** section of the repository. You can find detailed descriptions of proposed features and their technical implementations here:

## GitHub Wiki Pages

GitHub Wiki Pages is contains of **SIPS (SPHINX IMPLEMENTATION PROPOSALS)** you can join to review, discussions, or suggest improvements to existing proposals ideas. To contribute just visit to the **[GitHub Wiki](https://github.com/sphinx-core/sips/wiki).**

## Improvement Ideas

Here are some areas where contributions are most welcome:

1. Documentation: Help improve existing documentation or write tutorials and guides.
2. Testing: Write unit tests, integration tests, or perform manual testing to identify bugs.
3. Security: Contribute to making Sphinx-Core more secure by reviewing code or proposing post-quantum cryptographic methods.
4. Performance Optimization: Improve performance and scalability of the Sphinx-Core protocol.
5. Feature Requests: If you have ideas for new features, open an issue or create a proposal in the **[GitHub Wiki](https://github.com/sphinx-core/sips/wiki).**

##  License

This project is licensed under the MIT License - see the LICENSE file for details.

## By following this guide

you will be able to contribute to the Sphinx-Core project and help us build a quantum-resistant blockchain ecosystem.

