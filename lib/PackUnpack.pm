use MONKEY-TYPING;

my %dispatch;
my int $i = -1;
%dispatch.ASSIGN-KEY($_,$i = $i + 1) for <a A C H L n N S v V x Z>;

sub parse-template($template) is export {
    my int $i     = -1;
    my int $chars = $template.chars;
    my @template;
    while ($i = $i + 1) < $chars {
        my str $directive = substr($template,$i,1);
        X::Buf::Pack.new(:$directive).throw
          unless %dispatch.EXISTS-KEY($directive);

        my str $amount = ($i = $i + 1) < $chars
          ?? substr($template,$i,1)
          !! "1";

        if %dispatch.EXISTS-KEY($amount) {
            @template.push( (%dispatch.AT-KEY($directive),1) );
            $i = $i - 1;  # went one too far
        }
        elsif $amount eq '*' {
            @template.push( (%dispatch.AT-KEY($directive),$amount) );
        }
        elsif $amount.unival === NaN {
            X::Buf::Pack.new(:directive($directive ~ $amount)).throw;
        }
        else {  # a number
            my $next;
            $amount = $amount ~ $next
              while ($i = $i + 1) < $chars
                && !(($next = substr($template,$i,1)).unival === NaN);
            @template.push( (%dispatch.AT-KEY($directive),+$amount) );
            $i = $i - 1; # went one too far
        }
    }

    @template;
}

dd parse-template("a*x234N");

proto sub pack(|) is export { * }
multi sub pack(Str $template, |c) { pack(parse-template($template),|c) }

multi sub pack(@template, *@items) {

    my $buf = Buf.new;
    my $amount;

    sub shift-per-byte(int \number, int @shifts --> Nil) {
        $buf.push(number +> $_) for @shifts;
    }

    my int @NET2 = 0x08, 0x00;             # short, network (big-endian) order
    my int @NET4 = 0x18, 0x10, 0x08, 0x00; # long, network (big-endian) order
    my int @VAX2 = 0x00, 0x08;             # short, VAX (little-endian) order
    my int @VAX4 = 0x00, 0x08, 0x10, 0x18; # long, VAX (little-endian) order

    state @dispatch =
      -> {  # a
        my $data = (@items ?? @items.shift !! Buf.new);
        $data .= encode if $data ~~ Str;
        $amount = $data.cache.elems if $amount eq '*';
        $buf.append( (@$data, 0 xx *).flat[^$amount] );
      },
      -> {  # A
        my $data = (@items ?? @items.shift !! '').ords.cache;
        $amount = $data.elems if $amount eq '*';
        if @$data.first( -> $byte { $byte > 0x7f } ) -> $too-large {
            X::Buf::Pack::NonASCII.new(:char($too-large.chr)).throw;
        }
        $buf.append( (@$data, 0x20 xx *).flat[^$amount] );
      },
      -> {  # C
        $buf.append( @items.shift );
      },
      -> {  # H
        my $hex = @items ?? @items.shift !! '';
        $hex = $hex ~ '0' if $hex.chars % 2;
        $buf.append( $hex.comb(2).map( { :16($_) } ) );
      },
      -> {  # L
        my int $number = @items ?? @items.shift !! 0;
        shift-per-byte($number, @VAX4);
      },
      -> {  # n
        my int $number = @items ?? @items.shift !! 0;
        shift-per-byte($number, @NET2);
      },
      -> {  # N
        my int $number = @items ?? @items.shift !! 0;
        shift-per-byte($number, @NET4);
      },
      -> {  # S
        my int $number = @items ?? @items.shift !! 0;
        shift-per-byte($number, @VAX2);
      },
      -> {  # v
        my int $number = @items ?? @items.shift !! 0;
        shift-per-byte($number, @VAX2);
      },
      -> {  # V
        my int $number = @items ?? @items.shift !! 0;
        shift-per-byte($number, @VAX4);
      },
      -> {  # x
        $buf.append( 0x00 xx $amount ) unless $amount eq '*';
      },
      -> {  # Z
        X::NYI.new(feature => 'pack Z').throw;
      },
    ;

    for @template -> $todo {
        $amount = $todo.AT-POS(1);
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
            my $amount    = substr($unit,1);
            my $pa = $amount eq ''  ?? 1            !!
                     $amount eq '*' ?? @bytes.elems !! +$amount;

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
