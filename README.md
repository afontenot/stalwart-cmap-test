# stalwart-jmap-test

This short program uses the [jmapc](https://github.com/smkent/jmapc)
library to test certain features of the JMAP API provided by
[Stalwart](https://github.com/stalwartlabs/mail-server/).

In particular, the program will fetch an mailbox, read a list of
messages in that mailbox, and download all the message parts. This is
useful to verify that messages are downloaded successfully, and can be
easily modified to store messages and attachments if desired.

Developers may find the reusable class `Blob` useful, as it is capable
of parsing and modifying the base32 encoded strings that Stalwart uses
to identify data blobs such as email messages. For example, because the
strings actually encode metadata about the request, it is possible to
modify a blob to download a different byte range in a message, or to
prevent Stalwart from trying to decode the message.

## License

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
