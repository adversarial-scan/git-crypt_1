
git-crypt enables transparent encryption and decryption of files in a
git repository.  Files which you choose to protect are encrypted when
committed, and decrypted when checked out.  git-crypt lets you freely
share a repository containing a mix of public and private content.
git-crypt gracefully degrades, so developers without the secret key can
still clone and commit to a repository with encrypted files.  This lets
you store your secret material (such as keys or passwords) in the same
repository as your code, without requiring you to lock down your entire
repository.

git-crypt was written by Andrew Ayer <agwa at andrewayer dot name>.  For
more information, see <https://www.agwa.name/projects/git-crypt>.

Building git-crypt
------------------
See the [INSTALL.md](INSTALL.md) file.


Using git-crypt
---------------

Generate a secret key:

    git-crypt keygen /path/to/keyfile

Configure a repository to use encryption:

    cd repo
    git-crypt init /path/to/keyfile

Specify files to encrypt by creating a .gitattributes file:

    secretfile filter=git-crypt diff=git-crypt
    *.key filter=git-crypt diff=git-crypt

Like a .gitignore file, it can match wildcards and should be checked
into the repository.  Make sure you don't accidentally encrypt the
.gitattributes file itself!

Cloning a repository with encrypted files:

    git clone /path/to/repo
    cd repo
    git-crypt init /path/to/keyfile

That's all you need to do - after running `git-crypt init`, you can use
git normally - encryption and decryption happen transparently.

Current Status
--------------

The latest version of git-crypt is [0.3](NEWS.md), released on
2013-04-05.  git-crypt aims to be bug-free and reliable, meaning it
shouldn't crash, malfunction, or expose your confidential data.
However, it has not yet reached maturity, meaning it is not as
documented, featureful, or easy-to-use as it should be.  Additionally,
there may be backwards-incompatible changes introduced before version
1.0.

Development on git-crypt is currently focused on improving the user
experience, especially around setting up repositories.  There are also
plans to add additional key management schemes, such as
passphrase-derived keys and keys encrypted with PGP.

Security
--------

git-crypt is more secure that other transparent git encryption systems.
git-crypt encrypts files using AES-256 in CTR mode with a synthetic IV
derived from the SHA-1 HMAC of the file.  This is provably semantically
secure under deterministic chosen-plaintext attack.  That means that
although the encryption is deterministic (which is required so git can
distinguish when a file has and hasn't changed), it leaks no information
beyond whether two files are identical or not.  Other proposals for
transparent git encryption use ECB or CBC with a fixed IV.  These
systems are not semantically secure and leak information.

Limitations
-----------

git-crypt relies on git filters, which were not designed with encryption
in mind.  As such, git-crypt is not the best tool for encrypting most or
all of the files in a repository. Where git-crypt really shines is where
most of your repository is public, but you have a few files (perhaps
private keys named *.key, or a file with API credentials) which you
need to encrypt.  For encrypting an entire repository, consider using a
system like [git-remote-gcrypt](https://github.com/joeyh/git-remote-gcrypt)
instead.  (Note: no endorsement is made of git-remote-gcrypt's security.)

git-crypt does not encrypt file names, commit messages, or other metadata.

Files encrypted with git-crypt are not compressible.  Even the smallest
change to an encrypted file requires git to store the entire changed file,
instead of just a delta.

Files encrypted with git-crypt cannot be patched with git-apply, unless
the patch itself is encrypted.  To generate an encrypted patch, use `git
diff --no-textconv --binary`.  Alternatively, you can apply a plaintext
patch outside of git using the patch command.

Although git-crypt protects individual file contents with a SHA-1
HMAC, git-crypt cannot be used securely unless the entire repository is
protected against tampering (an attacker who can mutate your repository
can alter your .gitattributes file to disable encryption).  If necessary,
use git features such as signed tags instead of relying solely on
git-crypt for integrity.

Mailing Lists
-------------

To stay abreast of, and provide input to, git-crypt development,
consider subscribing to one or both of our mailing lists:

* [Announcements](http://lists.cloudmutt.com/mailman/listinfo/git-crypt-announce)
* [Discussion](http://lists.cloudmutt.com/mailman/listinfo/git-crypt-discuss)
