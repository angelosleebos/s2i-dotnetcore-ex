#!/bin/bash

#First install Java (Required for ElasticSearch and Logstash)
apt update
apt install openjdk-8-jdk -y 

#Install NGINX
apt install nginx -y
sudo ufw app list

#Install ElasticSearch import the Elasticsearch public GPG key into APT
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add -

#Add Elastic Source list to APT
echo "deb https://artifacts.elastic.co/packages/6.x/apt stable main" | sudo tee -a /etc/apt/sources.list.d/elastic-6.x.list
apt update
sudo apt install elasticsearch

#Adjust values ​​in config file in /etc/elasticsearch/elasticsearch.yml
sed -i 's/#network.host: 192.168.0.1/network.host: 0.0.0.0/g' /etc/elasticsearch/elasticsearch.yml
sed -i 's/#http.port: 9200/http.port: 9200/g' /etc/elasticsearch/elasticsearch.yml
systemctl start elasticsearch
systemctl enable elasticsearch  #Elastic on startup

#Install Kibana from the ElasticSearch repository
apt install kibana
apt update
sed -i 's/#server.host: "localhost"/server.host: "0.0.0.0"/g' /etc/kibana/kibana.yml
systemctl enable kibana
systemctl start kibana

#Install logstash
apt install logstash
iptables -I INPUT -p tcp --dport 5044 -j ACCEPT
iptables -I INPUT -p tcp --dport 9200 -j ACCEPT
iptables-save > /etc/sysconfig/iptables

#Create a config file called 02-beats-input.conf where you will set up you filebeat input:
cat <<EOF | sudo tee /etc/logstash/conf.d/02-beats-input.conf
input {
    beats {
    port => 5044
    }
}
EOF
systemctl restart logstash

#Create an another config file for the syslog filters
cat <<EOF | sudo tee /etc/logstash/conf.d/10-syslog-filter.conf
filter {
    if [fileset][module] == "system" {
    if [fileset][name] == "auth" {
        grok {
        match => { "message" => ["%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sshd(?:\[%{POSINT:[system][auth][pid]}\])?: %{DATA:[system][auth][ssh][event]} %{DATA:[system][auth][ssh][method]} for (invalid user )?%{DATA:[system][auth][user]} from %{IPORHOST:[system][auth][ssh][ip]} port %{NUMBER:[system][auth][ssh][port]} ssh2(: %{GREEDYDATA:[system][auth][ssh][signature]})?",
                    "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sshd(?:\[%{POSINT:[system][auth][pid]}\])?: %{DATA:[system][auth][ssh][event]} user %{DATA:[system][auth][user]} from %{IPORHOST:[system][auth][ssh][ip]}",
                    "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sshd(?:\[%{POSINT:[system][auth][pid]}\])?: Did not receive identification string from %{IPORHOST:[system][auth][ssh][dropped_ip]}",
                    "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} sudo(?:\[%{POSINT:[system][auth][pid]}\])?: \s*%{DATA:[system][auth][user]} :( %{DATA:[system][auth][sudo][error]} ;)? TTY=%{DATA:[system][auth][sudo][tty]} ; PWD=%{DATA:[system][auth][sudo][pwd]} ; USER=%{DATA:[system][auth][sudo][user]} ; COMMAND=%{GREEDYDATA:[system][auth][sudo][command]}",
                    "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} groupadd(?:\[%{POSINT:[system][auth][pid]}\])?: new group: name=%{DATA:system.auth.groupadd.name}, GID=%{NUMBER:system.auth.groupadd.gid}",
                    "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} useradd(?:\[%{POSINT:[system][auth][pid]}\])?: new user: name=%{DATA:[system][auth][user][add][name]}, UID=%{NUMBER:[system][auth][user][add][uid]}, GID=%{NUMBER:[system][auth][user][add][gid]}, home=%{DATA:[system][auth][user][add][home]}, shell=%{DATA:[system][auth][user][add][shell]}$",
                    "%{SYSLOGTIMESTAMP:[system][auth][timestamp]} %{SYSLOGHOST:[system][auth][hostname]} %{DATA:[system][auth][program]}(?:\[%{POSINT:[system][auth][pid]}\])?: %{GREEDYMULTILINE:[system][auth][message]}"] }
        pattern_definitions => {
            "GREEDYMULTILINE"=> "(.|\n)*"
        }
        remove_field => "message"
        }
        date {
        match => [ "[system][auth][timestamp]", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
        }
        geoip {
        source => "[system][auth][ssh][ip]"
        target => "[system][auth][ssh][geoip]"
        }
    }
    else if [fileset][name] == "syslog" {
        grok {
        match => { "message" => ["%{SYSLOGTIMESTAMP:[system][syslog][timestamp]} %{SYSLOGHOST:[system][syslog][hostname]} %{DATA:[system][syslog][program]}(?:\[%{POSINT:[system][syslog][pid]}\])?: %{GREEDYMULTILINE:[system][syslog][message]}"] }
        pattern_definitions => { "GREEDYMULTILINE" => "(.|\n)*" }
        remove_field => "message"
        }
        date {
        match => [ "[system][syslog][timestamp]", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
        }
    }
    }
}
EOF

#And another log file for the Outputs
cat <<EOF | sudo tee /etc/logstash/conf.d/30-elasticsearch-output.conf
output {
    elasticsearch {
    hosts => ["localhost:9200"]
    manage_template => false
    index => "%{[@metadata][beat]}-%{[@metadata][version]}-%{+YYYY.MM.dd}"
    }
}
EOF

#Test Logstash config
sudo -u logstash /usr/share/logstash/bin/logstash --path.settings /etc/logstash -t
systemctl start logstash
systemctl enable logstash

#Install filebeat
apt install filebeat

#Disable Elasticsearch rules, because we use logstash
sed -i '148,150 s/^/#/' /etc/filebeat/filebeat.yml

#Uncomments of a number of rules so that Logstash is "activated"
sed -i '161 s/#//' /etc/filebeat/filebeat.yml
sed -i '163 s/#//' /etc/filebeat/filebeat.yml

#Let's enable this filebeat
filebeat modules enable system

#Load a template to elasticsearch
filebeat setup --template -E output.logstash.enabled=false -E 'output.elasticsearch.hosts=["localhost:9200"]'

#Load dasboard
filebeat setup -e -E output.logstash.enabled=false -E output.elasticsearch.hosts=['localhost:9200'] -E setup.kibana.host=localhost:5601

#Enable Filebeat
systemctl start filebeat
systemctl enable filebeat