use v6.c;

use MONKEY-TYPING;

my %dispatch;
{
    my int $i = -1;
    %dispatch.ASSIGN-KEY($_,$i = $i + 1)
      for <a A C H I L n N Q S v V x Z>;
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

        if %dispatch.EXISTS-KEY($repeat) {
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

dd parse-template("a*x234N");
dd pack("a*aa2",<a bb ccc>);
dd pack("A*A*A*",<a bb ccc>);
dd pack("H*","123456789abcdef");
dd pack("N*",1,2,3);
dd pack("N*",4,5,6);

proto sub pack(|) is export { * }
multi sub pack(Str $template, |c) { pack(parse-template($template),|c) }
multi sub pack(@template, *@items) {
    my $buf = Buf.new;
    my $repeat;
    my int $pos   = 0;
    my int $elems = @items.elems; 

    sub repeated-shift-per-byte(int @shifts) {
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

    # make sure this has the same order as the %dispatch initialization
    my @dispatch =
      -> {  # a
        my $data = $pos < $elems ?? @items.AT-POS($pos++) !! Buf.new;
        $data .= encode if $data ~~ Str;
        $repeat = $data.cache.elems if $repeat eq '*';
        $buf.append( (@$data, 0 xx *).flat[^$repeat] );
      },
      -> {  # A
        my $data = $pos < $elems ?? @items.AT-POS($pos++).ords.cache !! ();
        $repeat = $data.elems if $repeat eq '*';
        if @$data.first( -> $byte { $byte > 0x7f } ) -> $too-large {
            X::Buf::Pack::NonASCII.new(:char($too-large.chr)).throw;
        }
        $buf.append( (@$data, 0x20 xx *).flat[^$repeat] );
      },
      -> { $buf.append( $pos < $elems ?? @items.AT-POS($pos++) !! 0 ) }, # C
      -> {  # H
        $repeat = @items if $repeat eq '*';
        for ^$repeat {
            my $hex = $pos < $elems ?? @items.AT-POS($pos++) !! '';
            $hex = $hex ~ '0' if $hex.chars % 2;
            $buf.append( $hex.comb(2).map( { :16($_) } ) );
        }
      },
      -> { repeated-shift-per-byte(@NAT)  }, # I
      -> { repeated-shift-per-byte(@VAX4) }, # L
      -> { repeated-shift-per-byte(@NET2) }, # n
      -> { repeated-shift-per-byte(@NET4) }, # N
      -> { repeated-shift-per-byte(@VAX8) }, # Q
      -> { repeated-shift-per-byte(@VAX2) }, # S
      -> { repeated-shift-per-byte(@VAX2) }, # v
      -> { repeated-shift-per-byte(@VAX4) }, # V
      -> { $buf.append( 0x00 xx $repeat ) unless $repeat eq '*' }, # x
      -> { X::NYI.new(feature => 'pack Z').throw }, # Z
    ;

    for @template -> $todo {
        $repeat = $todo.AT-POS(1);
        @dispatch.AT-POS($todo.AT-POS(0))();
    }

    $buf
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
