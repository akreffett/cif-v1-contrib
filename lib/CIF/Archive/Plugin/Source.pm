package CIF::Archive::Plugin::Source;
use base 'CIF::Archive::Plugin';

use strict;
use warnings;

use Iodef::Pb::Simple qw(iodef_confidence);
use Digest::SHA qw/sha1_hex/;

sub insert {
    my $class = shift;
    my $data = shift;

    return unless($class->test_datatype($data));
    return unless(ref($data->{'data'}) eq 'IODEFDocumentType');

    my $doc = $data->{'data'};

    my @ids;
    foreach my $i (@{$doc->get_Incident()}) {
        my $source = $i->get_IncidentID()->get_name();

        next unless($source);

        my $confidence = iodef_confidence($i);
        $confidence = @{$confidence}[0]->get_content();

        my $hash = sha1_hex($source);
        my $id = $class->insert_hash({
            uuid        =>  $data->{'uuid'},
            guid        =>  $data->{'guid'},
            confidence  =>  $confidence,
            reporttime  =>  $data->{'reporttime'},
        }, $hash);

        push(@ids, $id);
    }

    return (undef,\@ids);
}

1;
