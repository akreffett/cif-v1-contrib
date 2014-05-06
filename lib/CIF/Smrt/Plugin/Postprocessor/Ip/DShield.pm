package CIF::Smrt::Plugin::Postprocessor::Ip::DShield;
use base 'CIF::Smrt::Plugin::Postprocessor::Ip';

use strict;
use warnings;

use CIF qw/generate_uuid_random/;
use Iodef::Pb::Simple ':all';
use REST::Client;
use Text::Trim;
use XML::Smart;

sub process {
    my $class = shift;
    my $smrt = shift;
    my $data = shift;

    my $client = REST::Client->new({
        host    =>  'https://secure.dshield.org/api',
    });
    $client->getUseragent()->proxy(['http','https','ftp'], $smrt->get_config()->{'proxy'}) if($smrt->get_config()->{'proxy'});

    my @new_ids;
    foreach my $i (@{$data->get_Incident()}){
        next unless($i->get_EventData());

        my $restriction = $i->get_restriction();
        my $assessment = $i->get_Assessment();

        my $confidence = @{$assessment}[0]->get_Confidence();
        $confidence = $confidence->get_content();
        $confidence = $class->degrade_confidence($confidence);

        my $guid;
        if(my $iad = $i->get_AdditionalData()){
            foreach (@$iad){
                next unless($_->get_meaning() =~ /^guid/);
                $guid = $_->get_content();
            }
        }

        my $altids = $i->get_RelatedActivity();
        $altids = $altids->get_IncidentID() if($altids);

        my $systems = iodef_systems($i);
        foreach my $system (@$systems){
            my @additional_data;
            my $nodes = (ref($system->get_Node()) eq 'ARRAY') ? $system->get_Node() : [ $system->get_Node() ];
            foreach my $node (@$nodes){
                my $addresses = (ref($node->get_Address()) eq 'ARRAY') ? $node->get_Address() : [ $node->get_Address() ];
                foreach my $addr (@$addresses){
                    next unless($class->is_ipv4($addr));
                    $client->GET("/ip/".$addr->get_content());
                    next unless($client->responseCode() eq '200');
                    my $XML = XML::Smart->new($client->responseContent());
                    next unless($XML->{ip});
                    my $packets = trim($XML->{ip}{count}->content());
                    my $attacks = trim($XML->{ip}{attacks}->content());
                    next unless($packets > 0 or $attacks > 0);
                    my $description = "Packets: $packets, Targets: $attacks";

                    my $id = IncidentIDType->new({
                        content     =>  generate_uuid_random(),
                        instance    =>  $smrt->get_instance(),
                        name        =>  'dshield',
                        restriction =>  $restriction,
                    });
                    my $new = Iodef::Pb::Simple->new({
                        address     =>  $addr->get_content(),
                        prefix      =>  trim($XML->{ip}{network}),
                        asn         =>  trim($XML->{ip}{as}),
                        asn_desc    =>  trim($XML->{ip}{asname}),
                        IncidentID  =>  $id,
                        assessment  =>  'suspicious',
                        description =>  $description,
                        confidence  =>  50,
                        restriction =>  $restriction,
                        Contact     =>  $i->get_Contact(),
                        guid        =>  $guid,
                        alternativeid               =>  $client->getHost()."/ip/".$addr->get_content(),
                        alternativeid_restriction   =>  'public',
                    });
                    push(@additional_data, ExtensionType->new({
                        dtype       =>  ExtensionType::DtypeType::dtype_type_string(),
                        meaning     =>  'dshield',
                        formatid    =>  'ip',
                        content     =>  $XML->data(nometa => 1, noheader => 1),
                    }));

                    push(@new_ids, @{$new->get_Incident()}[0]);
                    push(@$altids, $id);
                }
            }

            next unless(@additional_data);
            if ($system->get_AdditionalData()) {
                push(@{$system->get_AdditionalData()}, @additional_data);
            } else {
                $system->set_AdditionalData(\@additional_data);
            }
        }
    }

    return (\@new_ids);
}

1;
