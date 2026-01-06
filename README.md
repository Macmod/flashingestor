<p align="center">
  <h1 align="center"><b>flashingestor</b></h1>
  <p align="center"><i>A TUI for Active Directory collection.</i></p>
</p>

![GitHub Release](https://img.shields.io/github/v/release/Macmod/flashingestor) ![](https://img.shields.io/github/go-mod/go-version/Macmod/flashingestor) ![](https://img.shields.io/github/languages/code-size/Macmod/flashingestor) ![](https://img.shields.io/github/license/Macmod/flashingestor) ![](https://img.shields.io/github/actions/workflow/status/Macmod/flashingestor/release.yml) [![Go Report Card](https://goreportcard.com/badge/github.com/Macmod/flashingestor)](https://goreportcard.com/report/github.com/Macmod/flashingestor) ![GitHub Downloads](https://img.shields.io/github/downloads/Macmod/flashingestor/total) [<img alt="Twitter Follow" src="https://img.shields.io/twitter/follow/MacmodSec?style=for-the-badge&logo=X&color=blue">](https://twitter.com/MacmodSec)

# Philosophy

The main goals of this project are:

1. Be a **full data ingestor** compatible with BloodHound CE
2. Be faster, less noisy, and more customizable than other collectors
3. Be a friendly TUI (terminal user interface) with progress tracking

This is still a *beta* version, released just to demonstrate the concept - don't expect everything to work perfectly. If you find any bugs pleasee contribute with issues, PRs or discussions 🙂

# Implementation Details

`Flashingestor` implements 3 basic separate steps `LDAP Ingestion`, `Remote Collection` and `Conversion`, contrary to other collectors which run the specified methods in a single step:

- **Ingest** (`Ctrl+l`) - Collects raw object attributes' data from LDAP and stores that under `output/ldap` into intermediate `msgpack` files. Queries can be customized in `config.yaml`.

- **Remote** (`Ctrl+r`) - Reads these intermediate files into memory, computes the list of computers to collect, and performs a series of RPC/HTTP requests to obtain relevant remote information for `Computer` and `EnterpriseCA` objects, which are stored under `output/remote`. DNS lookups are performed before running Remote Collection.

- **Convert** (`Ctrl+s`) - Reads the intermediate files into memory, merges information from the ingestion and remote collection steps, and generates a Bloodhound-compatible dump under `output/bloodhound` - this step is entirely offline.

The main difference resource-wise is that `flashingestor` needs a bit more space to store the intermediate `msgpack` files, and it takes a bit of time to convert them into BloodHound format, but the active steps `Ingest` & `Remote` *should* be relatively efficient in terms of traffic, CPU & memory.

## Not Implemented

### Remote Collection

* `GPOChanges` collection is not implemented for `Domain` / `OrganizationalUnit` types.
* `SmbInfo` and `Status` collections are not implemented for the `Computer` type.
* `HttpEnrollmentEndpoints` only works with a provided username/password.
* `HostingComputer` resolution for the `EnterpriseCA` type is still a basic implementation
* `AllowedToDelegateTo` / `ServicePrincipalNames` resolution is still a basic implementation
* `ldapsigning` is not collected for DC `Computer` objects; `ldapsepa` is prone to false positives.

# Installation
```bash
$ git clone https://github.com/Macmod/flashingestor
$ cd flashingestor
$ go build ./cmd/flashingestor
```

# Usage

First authenticate with one of the following:
```bash
# Anonymous
# [Requires dSHeuristics of 0000002 in the DirectoryServices object
#  and can have limited visibility due to lack of Read ACEs]
$ ./flashingestor -u '@<DOMAIN>' -p '' [...]

# User + Password
$ ./flashingestor -u <USER>@<DOMAIN> -p <PASSWORD> [-k] [...]

# User + NTHash
$ ./flashingestor -u <USER>@<DOMAIN> -H <NTHASH> [-k] [...]

# User + PFX
$ ./flashingestor -u <USER>@<DOMAIN> --pfx <PFXPATH> [--pfx-password <PFXPASS>] [-k] [...]

# User + PEM
$ ./flashingestor -u <USER>@<DOMAIN> --cert <PEMPATH> --key <KEYPATH> [-k] [...]

# User + AESKey
$ ./flashingestor -u <USER>@<DOMAIN> --aes-key <AESKEY> -k [...]

# User + Ticket
$ ./flashingestor -u <USER>@<DOMAIN> --ccache /path/to/ticket.ccache -k [...]
or
$ KRB5CCNAME=/path/to/ticket.ccache ./flashingestor -u <USER>@<DOMAIN> -k [...]
```

Then run the steps as desired. For a `DCOnly` collection, just run `Ctrl+l`, check whether the ingestion succeeded, and then run `Ctrl+s` to generate the final dump.

## DC discovery & DNS

It's always recommended to specify `--dc` and `--dns` to run `flashingestor`. If you don't specify `--dc`, `flashingestor` will try to find it with SRV / A lookups, which may add some initial delay to the `Ingest` step.

In that case, you must specify `--dns` if your standard DNS server is not aware of the domain (when AD-integrated DNS is in use, just point it to the DC that hosts it). Moreover, regardless of `--dc`, if you want to run the `Remote Collection` step and your DNS server is not aware of computers in the domain, then you must specify `--dns` for the lookups.

In environments with multiple DCs, you can also use the `dcprobe` utility to benchmark the latency to all DCs and find a good target candidate for the ingestion.

```bash
$ go build ./cmd/dcprobe
$ ./dcprobe --dns 192.168.88.6 -d creta.local -r 10
```

## Config file

If the config file is not present under the current directory as `config.yaml` or in the path provided via `--config`, the default options (the same as in the provided [config.yaml](config.yaml)) will be assumed - they are hardcoded in [config/fallback.go](config/fallback.go).

## Ingestion

The default queries in the provided `config.yaml` are designed with information needed by Bloodhound conversion in mind. You may choose to customize queries or attributes in `config.yaml`, but it's best to try to avoid removing needed attributes, and to avoid changing the meaning of the search filters.

If `recurse_trusts` is set to `true`, it'll try to ingest any trusted domains found recursively with the initial credential provided for ingestion.

If `search_forest` is set to `true`, it'll try to ingest domains that are part of the same forest as the initial domain from the `Configuration` partition - no additional queries will be issued, as this is already part of the default ingestion plan. Both options can be set at the same time, and `flashingestor` will only ingest any domain found once (either via a trust, or via the current forest).

If `recurse_trusts` is enabled and `recurse_feasible_only` is also set to true, it'll only try to ingest a trusted domain if the trust is (1) inbound/bidirectional and (2) either involves the initial domain, or is transitive. That means that outbound-only trusts won't be traversed, and apart from the first level of trusts, the ingestion paths stop at nontransitive trusts - if B trusts A nontransitively, then A can still authenticate into B; but if C also trusts B nontransitively, then A can't authenticate to C.
 
## Remote Collection

If you intend to run the remote collection step, check the enabled `methods` - these roughly correspond to the methods offered by SharpHound and can be used to toggle specific collections via RPC or HTTP.

The `--remote-*` arguments can be used to specify a separate set of credentials for remote collection. If you don't specify these credentials, `flashingestor` will try to use the same credentials for the user provided in the standard ingestion arguments (`--user`, `--password`, etc).

A local admin can also be used for remote collection by specifying `--remote-user Administrator@.`, for example, but the effectiveness of this approach will depend on whether the account is the built-in administrator or not, and on the values of the `FilterAdministratorToken` / `LocalAccountTokenFilterPolicy` registry keys. For more detail on this behavior, refer to [Pass-the-Hash Is Dead: Long Live LocalAccountTokenFilterPolicy](https://specterops.io/blog/2017/03/16/pass-the-hash-is-dead-long-live-localaccounttokenfilterpolicy/)

## Conversion

The options `compress_output` and `cleanup_after_compression` can help keep the disk usage small. After loading the final dump in Bloodhound you can safely delete the files under `output/ldap` and `output/remote` manually if you don't have an use for them, but an interesting use case is keeping these files to look up important information and to avoid having to run the full collection from time to time.

The primary purpose of the `msgpack` files under the `output/ldap` and `output/remote` files is to serve as an intermediary format to segregate responsibilities for the entire process, but these files can also be used as a source of information by converting them to JSON - this way you don't have to look up raw object attributes or remote collection results:

```
$ go build ./cmd/ingest2json
$ ./ingest2json -in output/ldap/YOURDOMAIN/SelectedFile.msgpack  -out output.json
```

A nice way of inspecting these files would be to use [JQ](https://jqlang.org/)/[FX](https://github.com/antonmedv/fx), or your favorite programming language 🙂

# Contributing

Contributions are welcome by [opening an issue](https://github.com/Macmod/godap/issues/new) or by [submitting a pull request](https://github.com/Macmod/godap/pulls).

# Acknowledgements

* Big thanks to SpecterOps for [BloodHound](https://github.com/SpecterOps/BloodHound), [SharpHound](https://github.com/SpecterOps/SharpHound) / [SharpHoundCommon](https://github.com/SpecterOps/SharpHoundCommon) and to dirkjanm for [BloodHound.py](https://github.com/dirkjanm/Bloodhound.py), which were the main references for this tool.

* Thanks to [rtpt-erikgeiser](https://github.com/rtpt-erikgeiser) & [RedTeamPentesting](https://github.com/RedTeamPentesting/adauth) for [adauth](https://github.com/RedTeamPentesting/adauth) and to [p0dalirius](https://github.com/p0dalirius) for [winacl](https://github.com/TheManticoreProject/winacl), both really useful libraries.

* Thanks to [oiweiwei](https://github.com/oiweiwei) for [go-msrpc](https://github.com/oiweiwei/go-msrpc), as his library made it possible to implement remote collection methods based on RPCs.

# Known Issues

* Almost all properties implemented in SharpHound are supported, but there are many architectural differences between this tool and SharpHound, so don't expect the output to match the official implementation exactly (with exception of eventual bugs). Key differences may arise especially for the more complex implementations, such as remote collections via RPC and collections related to CA/certificate abuse.

* Tests are currently not implemented and I have only tested a small subset of features manually.

# License
The MIT License (MIT)

Copyright (c) 2023 Artur Henrique Marzano Gonzaga

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
