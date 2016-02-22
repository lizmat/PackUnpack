use v6.c;

use MONKEY-TYPING;

my %dispatch;
{
    my int $i = -1;
    %dispatch.ASSIGN-KEY($_,$i = $i + 1)
      for <a A c C h H i I l L n N q Q s S v V x Z>;   # Q fix highlighting
}
my int $bits = $*KERNEL.bits;

# this need to be conditional on the endianness of the system
my int @NET2 = 0x08,0x00;              # short, network (big-endian) order
my int @NET4 = 0x18,0x10,0x08,0x00;                     # long
my int @NET8 = 0x38,0x30,0x28,0x20,0x18,0x10,0x08,0x00; # quad
my int @VAX2 = 0x00,0x08;              # short, VAX (little-endian) order
my int @VAX4 = 0x00,0x08,0x10,0x18;                     # long
my int @VAX8 = 0x00,0x08,0x10,0x18,0x20,0x28,0x30,0x38; # quad
my int @NAT  = $bits == 32 ?? @VAX4 !! @VAX8;           # native

dd parse-template("a*x234N");
dd pack("a*aa2",<a bb ccc>);
dd pack("A*A*A*",<a bb ccc>);
dd pack("Z*Z5Z2",<a bb ccc>);
dd pack("h*","2143");
dd pack("CH*",42,"1234");
dd pack("N*",1,2,3);
dd pack("N*",4,5,6);
dd pack("x5");

sub parse-template($template) is export {
    my int $i     = -1;
    my int $chars = $template.chars;
    my @template;
    while ($i = $i + 1) < $chars {
        my str $directive = substr($template,$i,1);
        X::Buf::Pack.new(:$directive).throw
          unless %dispatch.EXISTS-KEY($directive);

        my str $repeat = ($i = $i + 1) < $chars
          ?? substr($template,$i,1)
          !! "1";

        if %dispatch.EXISTS-KEY($repeat) {  # repeat factor is next directive
            @template.push( (%dispatch.AT-KEY($directive),1) );
            $i = $i - 1;  # went one too far
        }
        elsif $repeat eq '*' {
            @template.push( (%dispatch.AT-KEY($directive),$repeat) );
        }
        elsif $repeat.unival === NaN {
            X::Buf::Pack.new(:directive($directive ~ $repeat)).throw;
        }
        else {  # a number
            my $next;
            $repeat = $repeat ~ $next
              while ($i = $i + 1) < $chars
                && !(($next = substr($template,$i,1)).unival === NaN);
            @template.push( (%dispatch.AT-KEY($directive),+$repeat) );
            $i = $i - 1; # went one too far
        }
    }

    @template;
}

proto sub pack(|) is export { * }
multi sub pack(Str $template, |c) { pack(parse-template($template),|c) }
multi sub pack(@template, *@items) {
    my $buf = Buf.new;
    my $repeat;
    my int $pos   = 0;
    my int $elems = @items.elems; 

    sub repeated-shift-per-byte(int @shifts --> Nil) {
        if $repeat eq '*' {
            for ^$elems {
                my int $number = @items.AT-POS($pos++);
                $buf.push($number +> $_) for @shifts;
            }
        }
        else {
            for ^$repeat {
                my int $number = $pos < $elems ?? @items.AT-POS($pos++) !! 0;
                $buf.push($number +> $_) for @shifts;
            }
        }
    }
    sub fill($data,\filler,\last-must-be-null --> Nil) {
        my int $i     = -1;
        my int $elems = +$data;
        if $repeat eq "*" {
            $buf.push($data.AT-POS($i)) while ($i = $i + 1) < $elems;
            $buf.push(filler) if last-must-be-null;
        }
        elsif $repeat <= $elems {
            $buf.push($data.AT-POS($i)) while ($i = $i + 1) < $repeat;
            $buf.AT-POS($buf.elems - 1) = 0 if last-must-be-null;
        }
        else {
            $buf.push($data.AT-POS($i)) while ($i = $i + 1) <  $elems;
            $buf.push(filler)           while ($i = $i + 1) <= $repeat;
        }
    }
    sub from-hex(\hex,\flip --> Nil) {
        my int $chars = hex.chars;
        if $chars % 2 {
            hex    = hex ~ '0';
            $chars = $chars + 1;
        }
        my int $i = -2;
        if flip {
            $buf.append( :16(substr(hex,$i,2).flip) )
              while ($i = $i + 2) < $chars;
        }
        else {
            $buf.append( :16(substr(hex,$i,2)) )
              while ($i = $i + 2) < $chars;
        }
    }
    sub ascii() {
        my $data = @items.AT-POS($pos++).ords.cache;
        if $data.first( -> $byte { $byte > 0x7f } ) -> $too-large {
            X::Buf::Pack::NonASCII.new(:char($too-large.chr)).throw;
        }
        $data
    }
    sub one(--> Nil) {
        $buf.append( $pos < $elems ?? @items.AT-POS($pos++) !! 0 )
    }
    sub hex(\flip --> Nil) {
        $repeat = @items - $pos if $repeat eq '*' || $repeat > @items - $pos;
        from-hex(@items.AT-POS($pos++),flip) for ^$repeat;
    }

    # make sure this has the same order as the %dispatch initialization
    my @dispatch =
      -> --> Nil {  # a
        if $pos < $elems {
            my $data = @items.AT-POS($pos++);
            fill($data ~~ Str ?? $data.encode !! $data,0,0);
        }
        else {
            fill((),0,0);
        }
      },
      -> --> Nil { fill( $pos < $elems ?? ascii() !! (),0x20,0) },  # A
      -> --> Nil { one() },  # c
      -> --> Nil { one() },  # C
      -> --> Nil { hex(0) }, # h
      -> --> Nil { hex(1) }, # H
      -> --> Nil { repeated-shift-per-byte(@NAT)  },     # i
      -> --> Nil { repeated-shift-per-byte(@NAT)  },     # I
      -> --> Nil { repeated-shift-per-byte(@VAX4) },     # l
      -> --> Nil { repeated-shift-per-byte(@VAX4) },     # L
      -> --> Nil { repeated-shift-per-byte(@NET2) },     # n
      -> --> Nil { repeated-shift-per-byte(@NET4) },     # N
      -> --> Nil { repeated-shift-per-byte(@VAX8) },     # q
      -> --> Nil { repeated-shift-per-byte(@VAX8) },     # Q
      -> --> Nil { repeated-shift-per-byte(@VAX2) },     # s
      -> --> Nil { repeated-shift-per-byte(@VAX2) },     # S
      -> --> Nil { repeated-shift-per-byte(@VAX2) },     # v
      -> --> Nil { repeated-shift-per-byte(@VAX4) },     # V
      -> --> Nil { fill((),0,0) unless $repeat eq '*' }, # x
      -> --> Nil { fill( $pos < $elems ?? ascii() !! (),0x20,1) },  # Z
    ;

    for @template -> $todo {
        $repeat = $todo.AT-POS(1);
        @dispatch.AT-POS($todo.AT-POS(0))();
    }

    $buf
}

proto sub unpack(|) is export { * }
multi sub unpack(Str $template, Blob:D \b) {
    unpack(parse-template($template),b)
}
multi sub unpack(@template, Blob:D \b) {
    my @result;
    my $repeat;
    my int $pos   = 0;
    my int $elems = b.elems; 

    sub reassemble-string($filler?) {
        my @string;
        if $repeat eq "*" || $pos + $repeat > $elems {
            $pos = $pos - 1;
            @string.push(b.ATPOS($pos)) while ($pos = $pos + 1) < $elems;
        }
        else {
            @string.push(b.ATPOS($pos++)) for ^$repeat;
        }
        if defined($filler) {
            my int $i = @string.elems;
            @string.pop
              while ($i = $i - 1) >= 0 && @string.AT-POS($i) == $filler;
        }
        @result.push(chrs(@string));
    }
    sub reassemble-int(int @shifts) {
    }

    # make sure this has the same order as the %dispatch initialization
    my @dispatch =
      -> --> Nil { reassemble-string() },      # a
      -> --> Nil { reassemble-string(0x20) },  # A
      -> --> Nil {  # c
#        $buf.append( $pos < $elems ?? @items.AT-POS($pos++) !! 0 )
      },
      -> --> Nil {  # C
#        $buf.append( $pos < $elems ?? @items.AT-POS($pos++) !! 0 )
      },
      -> --> Nil {  # h
#        $repeat = @items - $pos if $repeat eq '*' || $repeat > @items - $pos;
#        from-hex(@items.AT-POS($pos++),1) for ^$repeat;
      },
      -> --> Nil {  # H
#        $repeat = @items - $pos if $repeat eq '*' || $repeat > @items - $pos;
#        from-hex(@items.AT-POS($pos++),0) for ^$repeat;
      },
      -> --> Nil { reassemble-int(@NAT)  },     # i
      -> --> Nil { reassemble-int(@NAT)  },     # I
      -> --> Nil { reassemble-int(@VAX4) },     # l
      -> --> Nil { reassemble-int(@VAX4) },     # L
      -> --> Nil { reassemble-int(@NET2) },     # n
      -> --> Nil { reassemble-int(@NET4) },     # N
      -> --> Nil { reassemble-int(@VAX8) },     # q
      -> --> Nil { reassemble-int(@VAX8) },     # Q
      -> --> Nil { reassemble-int(@VAX2) },     # s
      -> --> Nil { reassemble-int(@VAX2) },     # S
      -> --> Nil { reassemble-int(@VAX2) },     # v
      -> --> Nil { reassemble-int(@VAX4) },     # V
      -> --> Nil { }, # x
      -> --> Nil { reassemble-string(0) },  # Z
    ;

    for @template -> $todo {
        $repeat = $todo.AT-POS(1);
        @dispatch.AT-POS($todo.AT-POS(0))();
    }

    @result
}

=finish

augment class Buf {

    proto method unpack(|) { * }
    multi method unpack(Blob:D: Str:D $template) {
        self.unpack($template.comb(/<[a..zA..Z]>[\d+|'*']?/))
    }
    multi method unpack(Blob:D: @template) {
        nqp::isnull(nqp::getlexcaller('EXPERIMENTAL-PACK')) and X::Experimental.new(
            feature => "the 'unpack' method",
            use     => "pack"
        ).throw;
        my @bytes = self.list;
        my @fields;
        for @template -> $unit {
            my $directive = substr($unit,0,1);
            my $repeat    = substr($unit,1);
            my $pa = $repeat eq ''  ?? 1            !!
                     $repeat eq '*' ?? @bytes.elems !! +$repeat;

            given $directive {
                when 'a' | 'A' | 'Z' {
                    @fields.push: @bytes.splice(0, $pa).map(&chr).join;
                }
                when 'H' {
                    my str $hexstring = '';
                    for ^$pa {
                        my $byte = shift @bytes;
                        $hexstring ~= ($byte +> 4).fmt('%x')
                                    ~ ($byte % 16).fmt('%x');
                    }
                    @fields.push($hexstring);
                }
                when 'x' {
                    splice @bytes, 0, $pa;
                }
                when 'C' {
                    @fields.append: @bytes.splice(0, $pa);
                }
                when 'S' | 'v' {
                    for ^$pa {
                        last if @bytes.elems < 2;
                        @fields.append: shift(@bytes)
                                    + (shift(@bytes) +< 0x08);
                    }
                }
                when 'L' | 'V' {
                    for ^$pa {
                        last if @bytes.elems < 4;
                        @fields.append: shift(@bytes)
                                    + (shift(@bytes) +< 0x08)
                                    + (shift(@bytes) +< 0x10)
                                    + (shift(@bytes) +< 0x18);
                    }
                }
                when 'n' {
                    for ^$pa {
                        last if @bytes.elems < 2;
                        @fields.append: (shift(@bytes) +< 0x08)
                                    + shift(@bytes);
                    }
                }
                when 'N' {
                    for ^$pa {
                        last if @bytes.elems < 4;
                        @fields.append: (shift(@bytes) +< 0x18)
                                    + (shift(@bytes) +< 0x10)
                                    + (shift(@bytes) +< 0x08)
                                    + shift(@bytes);
                    }
                }
                X::Buf::Pack.new(:$directive).throw;
            }
        }

        return |@fields;
    }
}

# vim: ft=perl6 expandtab sw=4
