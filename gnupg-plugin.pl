#!/usr/bin/env perl

# XEP-0027 jabber encryption support
# http://xmpp.org/extensions/xep-0027.html
# based on openpgp-plugin.pl by Michael Braun
# François Chavant aka khanku - 2009

use strict;
use warnings;

use Purple;

# Object Oriented Interface to GnuPG
# http://search.cpan.org/~agul/Crypt-GPG-1.63/GPG.pm
use Crypt::GPG;

# 15.05.2009 - 0.1 - proof of concept (decryption only)
# 16.05.2009 - 0.2 - now encrypting as well
our $VERSION = 0.2;

# Set your GPG key ID here
my $MY_KEY_ID = '0xDCC51FA6';
my $GPG_PATH  = '/usr/bin/gpg';
# armored output is the default with Crypt::GPG
# let's use gpg-agent as well
my $GPG_OPTS  = '--use-agent';

my %CONNSTATE = ();

our %PLUGIN_INFO = (perl_api_version => 2,
                    name        => 'GnuPG Plugin',
                    version     => '0.2',
                    summary     => 'Send and receive gpg encrypted messages.',
                    description => 'XEP-0027',
                    author      => 'François Chavant <code\@mail.chavant.info>',
                    url         => 'http://www.chavant.info',
                    load        => 'plugin_load',
                    unload      => 'plugin_unload',
);

sub plugin_init {
    return %PLUGIN_INFO;
}

sub decrypt {
    my $encrypted = "-----BEGIN PGP MESSAGE-----\n";
    $encrypted .= $_[0] . "\n-----END PGP MESSAGE-----";

    my $gpg = new Crypt::GPG;
    $gpg->gpgbin($GPG_PATH);
    $gpg->gpgopts('--armor');
    $gpg->debug(0);
    $gpg->secretkey($MY_KEY_ID);  # todo

    my $plaintext = $gpg->verify($encrypted);

    return (defined($plaintext)) ? $plaintext : '[decryption failed]';
}

sub encrypt {
    use Encode qw/encode/;

    my $msg = encode('UTF-8', shift);
    my $target = shift;

    my $gpg = new Crypt::GPG;
    $gpg->gpgbin($GPG_PATH);
    $gpg->gpgopts($GPG_OPTS);
    $gpg->debug(0);
    $gpg->encryptsafe(0);  # inquire

    my @encrypted = split(m/[\n]/, $gpg->encrypt($msg, $target));

    while ($encrypted[0] ne '') {
        shift @encrypted;
    }
    shift @encrypted;
    pop @encrypted;

    my $encrypted_body = join("\n", @encrypted);

    return (defined($encrypted_body)) ? $encrypted_body : '';
}

sub jabber_receiving_xmlnode_callback {
    my ($conn, $node, $data) = @_;
    my $encrypted_node =
        $node->get_child_with_namespace('x', 'jabber:x:encrypted');
    my $body = $node->get_child('body');
    if (defined($encrypted_node)) {
        Purple::Debug::misc('gnupg-plugin',
                            'received encrypted data: '
                                . $conn->get_display_name() . ', '
                                . $node->get_attrib('id')
                                . ", $data\n"
        );
        my $crypted   = $encrypted_node->get_data();
        my $plaintext = decrypt($crypted);
        my $newmsg    = "?GPG?$plaintext";
        $node->get_child('body')->insert_data($newmsg, length($newmsg));
    } else {
        if (defined($body)) {
            my $newmsg = '?NOGPG?';
            $node->get_child('body')->insert_data($newmsg, length($newmsg));
        }
    }
    $_[2] = $node;
    Purple::Debug::misc('gnupg-plugin',
                        "received:\n" . $node->to_str(0) . "\n");

    return;
}

sub receiving_im_msg_callback {
    my ($account, $from, $message, $conv, $flags, $data) = @_;
    my $xm = $_[2];

    Purple::Debug::misc('gnupg-plugin', "old body: $message\n");
    $message =~ s/<body>(.*)<\/body>/$1/;

    if ($message =~ /\?NOGPG\?$/) {
        $message
            =~ s/(.*)\?NOGPG\?$/<i><span title="unencrypted">[U]<\/span><\/i> $1/;
    } else {
        $message =~ s/.*\?GPG\?/<i><span title="encrypted">[E]<\/span><\/i> /;
    }

    $message = '<body>' . $message . '</body>';
    $_[2] = $message;
    Purple::Debug::misc('gnupg-plugin', "replaced by new body: $message\n");

    return;
}

sub jabber_sending_xmlnode_callback {
    my ($conn, $node, $data) = @_;

    # get text node
    my $bnode = $node->get_child('body');
    unless (defined($bnode)) { return; }

    # fetch target / connid
    my $target = $node->get_attrib('to');
    $target =~ s/\/.*//;    # name@host/path => remove path
    my $connid = $target;

    # not encrypted by default
    unless (exists($CONNSTATE{$connid})) { $CONNSTATE{$connid} = 0; }
    Purple::Debug::misc('gnupg-plugin', "sending to $target\n");

    # fetch message
    my $msg = $bnode->get_data();

    my $do_encrypt = $CONNSTATE{$connid};
    Purple::Debug::misc('gnupg-plugin', "sending message:\n$msg\n");

    # parse commands, decide on encryption
    if ($msg =~ /^enablegpg/i) {
        Purple::Debug::misc('gnupg-plugin', "enabling encryption\n");
        $CONNSTATE{$connid} = 1;
        $msg = 'The remote party *enabled* XEP-0027 (OpenPGP) encryption.';
        $do_encrypt = 1;
        info_enable_gpg($target);
    } elsif ($msg =~ /^disablegpg/i) {
        Purple::Debug::misc('gnupg-plugin', "disabling encryption\n");
        $CONNSTATE{$connid} = 0;
        $msg = 'The remote party *disabled* XEP-0027 (OpenPGP) encryption.';
        info_disable_gpg($target);
    }

    unless ($do_encrypt) { return; }

    # drop html node
    my $htmlbnode = $node->get_child('html');
    if (defined($htmlbnode)) { $htmlbnode->free(); }

    # encrypt data
    my $encrypted = encrypt($msg, $target);

    # error?
    if ($encrypted eq '') {
        Purple::Debug::misc('gnupg-plugin',
                            "encryption failed, notifying the other party\n");
        info_err_encrypt($target);

        # replace plain data with error message
        $msg = 'Failed to encrypt message.';
        $bnode->free();
        $node->new_child('body')->insert_data($msg, length($msg));
        $_[1] = $node;
        return;
    }

    # explanatory body
    $msg =
        '[ERROR: This message is encrypted, and you are unable to decrypt it.]';
    $bnode->free();
    $node->new_child('body')->insert_data($msg, length($msg));

    # and encrypted message in its namespace
    my $x = $node->new_child('x');
    $x->set_attrib('xmlns', 'jabber:x:encrypted');
    $x->insert_data($encrypted, length($encrypted));

    # ensure our new node is the one sent
    $_[1] = $node;
    Purple::Debug::misc('gnupg-plugin',
                        'sending new: ' . $node->to_str(0) . "\n");

    return;
}

sub info_enable_gpg {
    require Gtk2;

    my $target = shift;
    my $frame  = Gtk2::Window->new();
    my $dialog = Gtk2::MessageDialog->new(
                   $frame,
                   'destroy-with-parent',
                   'info',                             # message type
                   'ok',                               # which set of buttons?
                   "Encryption enabled for $target."
    );
    $dialog->run;
    $dialog->destroy;
    $frame->destroy;

    return;
}

sub info_disable_gpg {
    require Gtk2;

    my $target = shift;
    my $frame  = Gtk2::Window->new();
    my $dialog = Gtk2::MessageDialog->new(
                  $frame,
                  'destroy-with-parent',
                  'info',                              # message type
                  'ok',                                # which set of buttons?
                  "Encryption disabled for $target."
    );
    $dialog->run;
    $dialog->destroy;
    $frame->destroy;

    return;
}

sub info_err_encrypt {
    require Gtk2;

    my $target = shift;
    my $frame  = Gtk2::Window->new();
    my $dialog = Gtk2::MessageDialog->new(
          $frame,
          'destroy-with-parent',
          'error',                                     # message type
          'cancel',                                    # which set of buttons?
          "Could not encrypt message for $target.\n"
    );
    $dialog->run;
    $dialog->destroy;
    $frame->destroy;

    return;
}

sub plugin_load {
    my $plugin = shift;

    Purple::Debug::misc('gnupg-plugin',
                        "plugin_load() - GnuPG Plugin Loaded.\n");

    my $accounts_handle = Purple::Accounts::get_handle();
    my $jabber          = Purple::Find::prpl('prpl-jabber');
    Purple::Signal::connect($jabber,
                            'jabber-receiving-xmlnode',
                            $plugin,
                            \&jabber_receiving_xmlnode_callback,
                            'receiving jabber node'
    );

    Purple::Signal::connect($jabber,
                            'jabber-sending-xmlnode',
                            $plugin,
                            \&jabber_sending_xmlnode_callback,
                            'sending jabber node'
    );

    my $conv = Purple::Conversations::get_handle();
    Purple::Signal::connect($conv, 'receiving-im-msg', $plugin,
                            \&receiving_im_msg_callback,
                            'receiving im message');

    return;
}

sub plugin_unload {
    my $plugin = shift;
    Purple::Debug::misc('gnupgplugin',
                        "plugin_unload() - GnuPG Plugin Unloaded.\n");

    return;
}
