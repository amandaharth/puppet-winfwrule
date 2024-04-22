# Reference:
# https://puppet.com/docs/puppet/8/create_types_and_providers_resource_api.html

# When a Purge/Delete is done by Puppet, the firewall rule is set to DISABLED in Windows Firewall. It is NOT deleted from the system.
# This is by design.

require 'puppet/resource_api/simple_provider'

# Implementation for the Winfwrule type using the Resource API.
class Puppet::Provider::Winfwrule::Winfwrule < Puppet::ResourceApi::SimpleProvider 
    SCRIPT_PATH = 'ps/winfwrule.ps1' unless const_defined?(:SCRIPT_PATH)

    def get(context)
        JSON.parse(Puppet::Util::Execution.execute(['powershell.exe', '-ExecutionPolicy', 'Bypass', '-File', File.join(Puppet.settings[:libdir], SCRIPT_PATH), '-PuppetAction','get']), symbolize_names: true)
    end

    def create(context, name, should)
        output = Puppet::Util::Execution.execute(['powershell.exe', '-ExecutionPolicy', 'Bypass', '-Command', File.join(Puppet.settings[:libdir], SCRIPT_PATH), '-PuppetAction','create', format_powershell_args(should)])
        Puppet.debug output
    end

    def update(context, name, should)
        output = Puppet::Util::Execution.execute(['powershell.exe', '-ExecutionPolicy', 'Bypass', '-Command', File.join(Puppet.settings[:libdir], SCRIPT_PATH), '-PuppetAction','update', format_powershell_args(should)])
        Puppet.debug output
    end

    def delete(context, name)
        output = Puppet::Util::Execution.execute(['powershell.exe', '-ExecutionPolicy', 'Bypass', '-Command', File.join(Puppet.settings[:libdir], SCRIPT_PATH), '-PuppetAction','delete', '-Name', "'#{name.gsub(/'/,"''")}'"])
        Puppet.debug output
    end

    def format_powershell_args(should)
        # Iterate over contents of the 'should' hash except the :ensure key/val (ensure doesn't need to be passed to PowerShell)
        # Convert k (key) name e.g. local_address to PowerShell-style name LocalAddress
        # Add k(ey) to args array, prefixing key name with a hyphen so it can be passed as a PowerShell parameter name
        # If v(alue) is a ruby array, format it so it can be passed as a PowerShell array @() argument
        # If v(alue) is not an array, format it so it can be passed as a single-quoted string argument; if the string contains single quotes, double them up so PowerShell interprets the string correctly
        # Add v(alue) to args array
        # Return args array
        args = Array.new
        (should.select { |k, v| k != :ensure }).each do | k, v | 
            transformed_key = k.to_s.split('_').map(&:capitalize).join
            args << "-#{transformed_key}"
            if v.kind_of?(Array)
                v = "@(#{v.map { | val | "'#{val}'" }.join(",")})"
            else
                v = "'#{v.gsub(/'/,"''")}'"
            end
            args << "#{v}"
        end
        args
    end

    # Custom set method so we can pass and show more information about what we are deleting/disabling
    def set(context, changes)
        namevars = context.type.namevars

        changes.each do |name, change|
            is = if context.type.feature?('simple_get_filter')
                    change.key?(:is) ? change[:is] : (get(context, [name]) || []).find { |r| SimpleProvider.build_name(namevars, r) == name }
                else
                    change.key?(:is) ? change[:is] : (get(context) || []).find { |r| SimpleProvider.build_name(namevars, r) == name }
                end
            context.type.check_schema(is) unless change.key?(:is)

            should = change[:should]

            raise 'SimpleProvider cannot be used with a Type that is not ensurable' unless context.type.ensurable?

            is_ensure = is.nil? ? 'absent' : is[:ensure].to_s
            should_ensure = should.nil? ? 'absent' : should[:ensure].to_s

            name_hash = if namevars.length > 1
                            # pass a name_hash containing the values of all namevars
                            name_hash = {}
                            namevars.each do |namevar|
                                name_hash[namevar] = change[:should][namevar]
                            end
                            name_hash
                        else
                            name
                        end

            if is_ensure == 'absent' && should_ensure == 'present'
                context.creating(name) do
                    create(context, name_hash, should)
                end
            elsif is_ensure == 'present' && should_ensure == 'absent'
                context.deleting(name) do
                    # Customised: log the details of the rule that will be disabled
                    Puppet.info("Disabling rule '#{change.dig(:is, :name)}' which had the configuration: #{change.dig(:is)}")
                    delete(context, name_hash)
                end
            elsif is_ensure == 'present'
                context.updating(name) do
                    update(context, name_hash, should)
                end
            end
        end
    end

    def canonicalize(context, resources)
        resources.each do | r |
            r.each do | k, v | 
                if r[:"#{k}"].kind_of?(Array)
                    r[:"#{k}"] = r[:"#{k}"].sort_by{ |w| [w.downcase, w] }
                end
            end
        end
    end

end