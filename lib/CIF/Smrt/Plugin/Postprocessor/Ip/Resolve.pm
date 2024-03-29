package CIF::Smrt::Plugin::Postprocessor::Ip::Resolve;
use base 'CIF::Smrt::Plugin::Postprocessor::Ip';

use strict;
use warnings;

use CIF qw(generate_uuid_random);
use Iodef::Pb::Simple ':all';
use Regexp::Common qw/net/;

my @postprocessors = CIF::Smrt->plugins();
@postprocessors = grep(/Postprocessor::[0-9a-zA-Z_]+$/,@postprocessors);

sub process {
    my $class   = shift;
    my $smrt    = shift;
    my $data    = shift;
 
    my @alt_ids;
    my @new_incidents;
    
    foreach my $i (@{$data->get_Incident()}){
        next unless($i->get_EventData());
        my $source = $i->get_IncidentID()->get_name() || 'unknown';
        my $restriction = $i->get_restriction();
        
        my $assessment = $i->get_Assessment();
        my $impact = iodef_impacts_first($i);
        
        my $description = @{$i->get_Description}[0]->get_content();
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
        
        foreach my $e (@{$i->get_EventData()}){
            $restriction = $e->get_restriction() if($e->get_restriction());
            my @flows = (ref($e->get_Flow()) eq 'ARRAY') ? @{$e->get_Flow()} : $e->get_Flow();
            foreach my $f (@flows){
                my @systems = (ref($f->get_System()) eq 'ARRAY') ? @{$f->get_System()} : $f->get_System();
                foreach my $s (@systems){
                    my @nodes = (ref($s->get_Node()) eq 'ARRAY') ? @{$s->get_Node()} : $s->get_Node();
                    $restriction = $s->get_restriction() if($s->get_restriction());
                    my @additional_data;
                    my $service = $s->get_Service();
                    my ($protocol,$portlist);
                    if($service){
                        $service = @{$service}[0] if(ref($service) eq 'ARRAY');
                        $protocol = $service->get_ip_protocol();
                        $portlist = $service->get_Portlist();
                    }
                    foreach my $n (@nodes){
                        my $addresses = $n->get_Address();
                        $addresses = [$addresses] if(ref($addresses) eq 'AddressType');
                        foreach my $addr (@$addresses){
                            next unless($class->is_ipv4($addr) || $class->is_ipv6($addr));
                            my $ret = $class->resolve_ptr($addr->get_content());
                            foreach my $rr (@$ret){
                                next unless($rr->type() =~ /^PTR$/);
                                my $ptrdname = $rr->ptrdname;
                                next unless($ptrdname =~ /^[a-zA-Z0-9.-]+\.[a-z]{2,8}$/); 
                                push(@additional_data,ExtensionType->new({
                                        dtype       => ExtensionType::DtypeType::dtype_type_string(),
                                        formatid    => $rr->type(),
                                        meaning     => 'rdata',
                                        content     => $ptrdname,
                                }));
                                unless($source =~ /(active|passive)dns/) {
                                    my $id = IncidentIDType->new({
                                        content     => generate_uuid_random(),
                                        instance    => $smrt->get_instance(),
                                        name        => 'activedns',
                                        restriction => $restriction,
                                    });
                                    my $new = Iodef::Pb::Simple->new({
                                        description     => $addr->get_content().' IN PTR '.$ptrdname,
                                        address         => $ptrdname,
                                        IncidentID      => $id,
                                        assessment      => $impact->get_content()->get_content(),
                                        confidence      => $confidence,
                                        RelatedActivity => RelatedActivityType->new({
                                            IncidentID  => [ $i->get_IncidentID() ],
                                            restriction => $restriction,
                                        }),
                                        restriction     => $restriction,
                                        guid            => $guid,
                                        portlist        => $portlist,
                                        ip_protocol     => $protocol,
                                        AlternativeID   => $i->get_AlternativeID(),
                                    });
                                    # block against CDN's that might thrash us into a for-loop of darkness
                                    if($confidence > 15){
                                        foreach (@postprocessors){
                                            my $ret = $_->process($smrt,$new);
                                            push(@new_incidents,@$ret) if($ret);
                                        }
                                    }
                                    push(@new_incidents,@{$new->get_Incident()});
                                    push(@$altids,$id);
                                }
                            }
                        }
                    }
                    next unless($#additional_data > -1);
                    if($s->get_AdditionalData()){
                        push(@{$s->get_AdditionalData()},@additional_data);
                    } else {
                        $s->set_AdditionalData(\@additional_data);
                    }
                }
            }
        }
        if($altids){
            $i->set_RelatedActivity(
                RelatedActivityType->new({
                    IncidentID  => $altids,
                })
            );
        }
    }
    return(\@new_incidents);
}

1;
