PROJECTNAME = 'STSecurity'.freeze

begin
  require 'bundler'
  Bundler.configure
rescue LoadError
end

require 'pathname'
require 'xctool'

begin
  require 'stcoverage'
  require 'stcoveralls'
rescue LoadError
end

task :default => 'analyze'

desc "Clean #{PROJECTNAME}"
task :clean => [ 'ios' ].map { |x| 'clean:' + x }

namespace :clean do
  desc "Clean #{PROJECTNAME}"
  task :ios do IosSim.clean or fail end
end

desc "Analyze #{PROJECTNAME}"
task :analyze => [ 'ios' ].map { |x| 'analyze:' + x }

namespace :analyze do
  desc "Analyze #{PROJECTNAME}"
  task :ios do IosSim.analyze or fail end
end

desc "Execute #{PROJECTNAME}Tests"
task :test => [ 'ios' ].map { |x| 'test:' + x }

namespace :test do
  desc "Execute #{PROJECTNAME}Tests"
  task :ios do IosSim.test or fail end
end

if defined?(Stcoverage)
  desc "Calculate test coverage for #{PROJECTNAME}"
  task :coverage => [ 'ios' ].map { |x| 'coverage:' + x }

  namespace :coverage do
    desc "Calculate test coverage"
    task :ios do IosSim.coverage or fail end
  end

  if defined?(Stcoveralls)
    namespace :coveralls do
      desc "Submit coverage data to coveralls"
      task :ios do IosSim.coveralls or fail end
    end
  end
end


module BuildCommands
  def clean
    Xctool.exec(@xctool_args, 'clean')
  end

  def analyze
    Xctool.exec(@xctool_args, 'analyze', ['-failOnWarnings'])
  end

  def test
    xctool_args = @xctool_args + [
      '-configuration', 'Debug',
      'GCC_GENERATE_TEST_COVERAGE_FILES=YES',
      'GCC_INSTRUMENT_PROGRAM_FLOW_ARCS=YES',
    ]
    Xctool.exec(xctool_args, 'test')
  end

  if defined?(Stcoverage)
    def coverage
      cwd = Pathname.getwd
      cwds = cwd.to_s

      coverage = stcoverage

      source_lines = 0
      covered_lines = 0
      coverage.each do |k, v|
        next unless k.start_with? cwds

        path = Pathname.new k
        next unless path.file? && path.readable?

        relpath = path.relative_path_from cwd

        file_source_lines = v.count
        file_covered_lines = v.count {|k, v| v > 0}
        file_coverage_fraction = (file_covered_lines / file_source_lines.to_f unless file_source_lines == 0) || 0
        puts "#{relpath.to_s}: #{file_covered_lines}/#{file_source_lines} #{(file_coverage_fraction * 100).floor}%"

        source_lines += file_source_lines
        covered_lines += file_covered_lines
      end

      coverage_fraction = (covered_lines / source_lines.to_f unless source_lines == 0) || 0
      puts "Overall: #{(coverage_fraction * 100).floor}%"
      true
    end

    if defined?(Stcoveralls)
      def coveralls
        cov = stcoverage
        Stcoveralls.coveralls do |c|
          c.add_stcoverage_local(cov)
        end
      end
    end
  end

  private

  if defined?(Stcoverage)
    def stcoverage
      xctool_args = @xctool_args + [
        '-configuration', 'Debug',
      ]
      object_file_path = Xctool.platform_object_files_path(xctool_args)
      return {} if object_file_path.nil?
      object_file_path = Pathname.new(object_file_path)
      return {} unless object_file_path.exist?

      gcfilenames = object_file_path.children.map{ |c| c.cleanpath.to_s if c.fnmatch? '*.gc??' }.compact
      Stcoverage.coverage(gcfilenames)
    end
  end
end

class IosSim
  @xctool_args = [
    '-project', "#{PROJECTNAME}.xcodeproj",
    '-scheme', "#{PROJECTNAME}",
    '-sdk', 'iphonesimulator',
    'ONLY_ACTIVE_ARCH=NO',
  ].freeze

  extend BuildCommands
end
