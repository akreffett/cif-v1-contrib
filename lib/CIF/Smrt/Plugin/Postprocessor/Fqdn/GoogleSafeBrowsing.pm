package CIF::Smrt::Plugin::Postprocessor::Fqdn::GoogleSafeBrowsing;
use base 'CIF::Smrt::Plugin::Postprocessor::Fqdn';

use strict;
use warnings;

use threads;
use threads::shared;

use CIF qw/generate_uuid_random debug/;
use CIF::Smrt::Plugin::Postprocessor::Ip ();
use Iodef::Pb::Simple ':all';
use Net::Google::SafeBrowsing2;
use Net::Google::SafeBrowsing2::Sqlite;
use URI::Escape;

# Update lock
my $update_lock :shared;

sub process {
    my $class = shift;
    my $smrt = shift;
    my $data = shift;

    return unless ($smrt->get_config->{'gsb_key'});
    return unless ($smrt->get_config->{'gsb_db_file'});

    my $storage = Net::Google::SafeBrowsing2::Sqlite->new(file => $smrt->get_config->{'gsb_db_file'});
    my $gsb = Net::Google::SafeBrowsing2->new(key => $smrt->get_config->{'gsb_key'}, storage => $storage);
    $gsb->ua()->proxy(['http','https','ftp'], $smrt->get_config()->{'proxy'}) if($smrt->get_config()->{'proxy'});
    
    # Update the database
    {
        lock($update_lock);
        $gsb->update();
    }

    my $descriptions = iodef_descriptions($data);
    return if grep { /(whitelist|nameserver)/ } @{$descriptions};

    my @new_ids;
    foreach my $incident (@{$data->get_Incident()}) {
        next unless($incident->get_EventData());

        my $restriction = $incident->get_restriction();
        my $assessment = $incident->get_Assessment();
        my $impact = iodef_impacts_first($incident)->get_content()->get_content();
        next if ($impact =~ /(whitelist|nameserver)/);

        my $confidence = @{$assessment}[0]->get_Confidence();
        $confidence = $confidence->get_content();
        $confidence = $class->degrade_confidence($confidence);

        my $guid;
        if (my $iad = $incident->get_AdditionalData()) {
            foreach (@$iad) {
                next unless ($_->get_meaning() =~ /^guid/);
                $guid = $_->get_content();
            }
        }

        my $relatedids = $incident->get_RelatedActivity();
        $relatedids = $relatedids->get_IncidentID() if ($relatedids);

        foreach my $e (@{$incident->get_EventData()}) {
            $restriction = $e->get_restriction() if ($e->get_restriction());
            my @flows = (ref($e->get_Flow()) eq 'ARRAY') ? @{$e->get_Flow()} : $e->get_Flow();
            foreach my $f (@flows) {
                my @systems = (ref($f->get_System()) eq 'ARRAY') ? @{$f->get_System()} : $f->get_System();
                foreach my $s (@systems) {
                    my @nodes = (ref($s->get_Node()) eq 'ARRAY') ? @{$s->get_Node()} : $s->get_Node();
                    $restriction = $s->get_restriction() if($s->get_restriction());
                    my @additional_data;
                    foreach my $n (@nodes) {
                        my $addresses = $n->get_Address();
                        $addresses = [$addresses] if(ref($addresses) eq 'AddressType');
                        foreach my $addr (@$addresses) {
                            next unless($class->is_fqdn($addr) 
                                || CIF::Smrt::Plugin::Postprocessor::Ip->is_ipv4($addr) 
                                || CIF::Smrt::Plugin::Postprocessor::Ip->is_ipv6($addr));
                            my $url = $gsb->canonical_uri($addr->get_content())->as_string;
                            my $result = $gsb->lookup(url => $url);
                            next unless($result && $result =~ /(malware|phishing)/);
                            my $newid = IncidentIDType->new({
                                content         => generate_uuid_random(),
                                instance        => $smrt->get_instance(),
                                name            => 'googlesafebrowsing',
                                restriction     => $restriction,
                            });
                            my $newpb = Iodef::Pb::Simple->new({
                                address         => $addr->get_content(),
                                IncidentID      => $newid,
                                assessment      => $result,
                                description     => "Google Safe Browsing: $result",
                                confidence      => 95,
                                restriction     => $restriction,
                                Contact         => $incident->get_Contact(),
                                guid            => $guid,
                                alternativeid               => "https://sb-ssl.google.com/safebrowsing/api/lookup?client=cif&apikey="
                                    .uri_escape($smrt->get_config->{'gsb_key'})."&appver=1.0.0&pver=3.0&url=".uri_escape($addr->get_content()),
                                alternativeid_restriction   => 'public',
                            });
                            my $newad = ExtensionType->new({
                                dtype       =>  ExtensionType::DtypeType::dtype_type_string(),
                                meaning     =>  'googlesafebrowsing',
                                content     =>  $result,
                            });
                            push(@new_ids, @{$newpb->get_Incident()}[0]);
                            push(@$relatedids, $newid);
                            push(@additional_data, $newad);
                        }
                    }
                    if (@additional_data) {
                        if($s->get_AdditionalData()){
                            push(@{$s->get_AdditionalData()},@additional_data);
                        } else {
                            $s->set_AdditionalData(\@additional_data);
                        }
                    }
                }
            }
        }
        if ($relatedids) {
            $incident->set_RelatedActivity(
                RelatedActivityType->new({
                    IncidentID  => $relatedids,
                }),
            );
        }
    }

    return (\@new_ids);
}

1;
