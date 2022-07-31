require 'resolv'

module Agents
  class DnsRecordMonitorAgent < Agent
    include FormConfigurable
    can_dry_run!
    no_bulk_receive!
    default_schedule 'every_5m'

    description do
      <<-MD
      The Dns Record Monitor Agent agent checks if a new record is present for a domain and creates an event if needed.

      `debug` is used to verbose mode.

      `type` is the type of wanted record (possible to be all available).

      `changes_only` is only used to emit event about a currency's change.

      `expected_receive_period_in_days` is used to determine if the Agent is working. Set it to the maximum number of days
      that you anticipate passing without this Agent receiving an incoming Event.
      MD
    end

    event_description <<-MD
      Events look like this:

          {
            "domain": "XXXXXXXX.XXXXXXX",
            "type": "A",
            "value": "XXX.XX.XX.XX",
            "ttl": 300
          }
    MD

    def default_options
      {
        'debug' => 'false',
        'domain' => '',
        'expected_receive_period_in_days' => '2',
        'type' => 'A',
        'changes_only' => 'true'
      }
    end

    form_configurable :expected_receive_period_in_days, type: :string
    form_configurable :domain, type: :string
    form_configurable :changes_only, type: :boolean
    form_configurable :debug, type: :boolean
    form_configurable :type, type: :array, values: ['A', 'TXT', 'MX', 'NS', 'SOA', 'all']
    def validate_options
      errors.add(:base, "type has invalid value: should be 'A' 'TXT' 'MX' 'NS' 'SOA' 'all']") if interpolated['type'].present? && !%w(A TXT MX NS SOA all).include?(interpolated['type'])

      if options.has_key?('changes_only') && boolify(options['changes_only']).nil?
        errors.add(:base, "if provided, changes_only must be true or false")
      end

      unless options['domain'].present?
        errors.add(:base, "domain is a required field")
      end

      if options.has_key?('debug') && boolify(options['debug']).nil?
        errors.add(:base, "if provided, debug must be true or false")
      end

      unless options['expected_receive_period_in_days'].present? && options['expected_receive_period_in_days'].to_i > 0
        errors.add(:base, "Please provide 'expected_receive_period_in_days' to indicate how many days can pass before this Agent is considered to be not working")
      end
    end

    def working?
      event_created_within?(options['expected_receive_period_in_days']) && !recent_error_logs?
    end

    def check
      check_records
    end

    private

    def check_soa(type)
      result = []
      Resolv::DNS.open do |dns|
        ress = dns.getresources interpolated['domain'], Resolv::DNS::Resource::IN::SOA
        ress.each do |record|

          if interpolated['debug'] == 'true'
            log record
            log record.inspect
          end
          wanted_value = record.mname.to_s + " " + record.rname.to_s
          result << {
            domain: interpolated['domain'],
            type: type,
            value: wanted_value,
            serial: record.serial,
            refresh: record.refresh,
            retry: record.retry,
            expire: record.expire,
            minimum: record.minimum,
            ttl: record.ttl
          }
        end
      end
      if interpolated['debug'] == 'true'
        log result
      end
      if interpolated['changes_only'] == 'true'
        if result.to_s != memory['SOA'].to_s
          if !memory['SOA'].nil?
            last_status = memory['SOA']
            result.each do |record|
              found = false
              last_status.each do |recordbis|
                if record[:value] == recordbis['value']
                  found = true
                end
                if interpolated['debug'] == 'true'
                  log "record[:value] -> #{record['value']}"
                  log "recordbis['value'] -> #{recordbis['value']}"
                end
              end
              if found == false
                if interpolated['debug'] == 'true'
                  log "found is #{found}! so event created"
                  log record
                end
                create_event payload: record
              end
            end
            memory['SOA'] = result
          else
            result.each do |record|
              create_event payload: record
            end
            memory['SOA'] = result
          end
        end
      else
        create_event payload: result
        if result.to_s != memory['SOA']
          memory['SOA'] = result
        end
      end
    end

    def check_ns(type)
      result = []
      Resolv::DNS.open do |dns|
        ress = dns.getresources interpolated['domain'], Resolv::DNS::Resource::IN::NS
        ress.each do |record|

          if interpolated['debug'] == 'true'
            log record
            log record.inspect
          end
          result << {
            domain: interpolated['domain'],
            type: type,
            value: record.name.to_s,
            ttl: record.ttl
          }
        end
      end
      if interpolated['debug'] == 'true'
        log result
      end
      if interpolated['changes_only'] == 'true'
        if result.to_s != memory['NS'].to_s
          if !memory['NS'].nil?
            last_status = memory['NS']
            result.each do |record|
              found = false
              last_status.each do |recordbis|
                if record[:value] == recordbis['value']
                  found = true
                end
              end
              if found == false
                if interpolated['debug'] == 'true'
                  log "found is #{found}! so event created"
                  log record
                end
                create_event payload: record
              end
            end
            memory['NS'] = result
          else
            result.each do |record|
              create_event payload: record
            end
            memory['NS'] = result
          end
        end
      else
        create_event payload: result
        if result.to_s != memory['NS']
          memory['NS'] = result
        end
      end
    end

    def check_mx(type)
      result = []
      Resolv::DNS.open do |dns|
        ress = dns.getresources interpolated['domain'], Resolv::DNS::Resource::IN::MX
        ress.each do |record|

          if interpolated['debug'] == 'true'
            log record
            log record.inspect
          end
          result << {
            domain: interpolated['domain'],
            type: type,
            value: record.exchange.to_s,
            preference: record.preference,
            ttl: record.ttl
          }
        end
      end
      if interpolated['debug'] == 'true'
        log result
      end
      if interpolated['changes_only'] == 'true'
        if result.to_s != memory['MX'].to_s
          if !memory['MX'].nil?
            last_status = memory['MX']
            result.each do |record|
              found = false
              last_status.each do |recordbis|
                if record[:value] == recordbis['value']
                  found = true
                end
              end
              if found == false
                if interpolated['debug'] == 'true'
                  log "found is #{found}! so event created"
                  log record
                end
                create_event payload: record
              end
            end
            memory['MX'] = result
          else
            result.each do |record|
              create_event payload: record
            end
            memory['MX'] = result
          end
        end
      else
        create_event payload: result
        if result.to_s != memory['MX']
          memory['MX'] = result
        end
      end
    end

    def check_a(type)
      result = []
      Resolv::DNS.open do |dns|
        ress = dns.getresources interpolated['domain'], Resolv::DNS::Resource::IN::A
        ress.each do |record|

          if interpolated['debug'] == 'true'
            log record
            log record.inspect
          end
          result << {
            domain: interpolated['domain'],
            type: type,
            value: record.address.to_s,
            ttl: record.ttl
          }
        end
      end
      if interpolated['debug'] == 'true'
        log result
      end
      if interpolated['changes_only'] == 'true'
        if result.to_s != memory['A'].to_s
          if !memory['A'].nil?
            last_status = memory['A']
            result.each do |record|
              found = false
              last_status.each do |recordbis|
                if record[:value] == recordbis['value']
                  found = true
                end
#                if interpolated['debug'] == 'true'
#                  log "record[:value] -> #{record['value']}"
#                  log "recordbis['value'] -> #{recordbis['value']}"
#                end
              end
              if found == false
                if interpolated['debug'] == 'true'
                  log "found is #{found}! so event created"
                  log record
                end
                create_event payload: record
              end
            end
            memory['A'] = result
          else
            result.each do |record|
              create_event payload: record
            end
            memory['A'] = result
          end
        end
      else
        create_event payload: result
        if result.to_s != memory['A']
          memory['A'] = result
        end
      end
    end

    def check_txt(type)
      result = []
      Resolv::DNS.open do |dns|
        ress = dns.getresources interpolated['domain'], Resolv::DNS::Resource::IN::TXT
        ress.each do |record|

          if interpolated['debug'] == 'true'
            log record
            log record.inspect
          end
          result << {
            domain: interpolated['domain'],
            type: type,
            value: record.strings.join(""),
            ttl: record.ttl
          }
        end
      end
      if interpolated['debug'] == 'true'
        log result
      end
      if interpolated['changes_only'] == 'true'
        if result.to_s != memory['TXT'].to_s
          if !memory['TXT'].nil?
            last_status = memory['TXT']
            result.each do |record|
              found = false
              last_status.each do |recordbis|
                if record[:value] == recordbis['value']
                  found = true
                end
              end
              if found == false
                if interpolated['debug'] == 'true'
                  log "found is #{found}! so event created"
                  log record
                end
                create_event payload: record
              end
            end
            memory['TXT'] = result
          else
            result.each do |record|
              create_event payload: record
            end
            memory['TXT'] = result
          end
        end
      else
        create_event payload: result
        if result.to_s != memory['TXT']
          memory['TXT'] = result
        end
      end
    end


    def check_records

      case interpolated['type']
      when "A"
        check_a(interpolated['type'])
      when "TXT"
        check_txt(interpolated['type'])
      when "MX"
        check_mx(interpolated['type'])
      when "NS"
        check_ns(interpolated['type'])
      when "SOA"
        check_soa(interpolated['type'])
      when "all"
        check_a("A")
        check_txt("TXT")
        check_mx("MX")
        check_ns("NS")
        check_soa("SOA")
      else
        log "Error: type has an invalid value (#{type})"
      end
    end
  end
end
