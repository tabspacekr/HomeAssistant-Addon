import paho.mqtt.client as mqtt
import json
import time
import asyncio
import telnetlib # python3.13에서는 telnetlib이 사라지고 telnetlib3로 변경예정임
import threading
import socket

share_dir = '/share'
config_dir = '/data'
data_dir = '/seik'
version = 'v1.4.8'

def log(string):
    date = time.strftime('%Y-%m-%d %p %I:%M:%S', time.localtime(time.time()))
    print('{} [{}] {}'.format(version, date, string))
    return

def main(CONFIG, OPTION, device_list):
    def pad(value):
        value = int(value)
        return '0' + str(value) if value < 10 else str(value)

    def checksum(input_hex):
        try:
            input_hex = input_hex[:14]
            s1 = sum([int(input_hex[val], 16) for val in range(0, 14, 2)])
            s2 = sum([int(input_hex[val + 1], 16) for val in range(0, 14, 2)])
            s1 = s1 + int(s2 // 16)
            s1 = s1 % 16
            s2 = s2 % 16
            return input_hex + format(s1, 'X') + format(s2, 'X')
        except Exception as err:
            log('[ERROR] checksum(): {}'.format(err))
            return None

    def make_hex(k, input_hex, change):
        if input_hex:
            try:
                change = int(change)
                input_hex = '{}{}{}'.format(input_hex[:change - 1], int(input_hex[change - 1]) + k, input_hex[change:])
            except:
                pass
        return checksum(input_hex)

    def make_hex_temp(k, curTemp, setTemp, state):  # 온도조절기 16자리 (8byte) hex 만들기
        log("k = {}, curTemp = {}, setTemp = {}, state = {}".format(k, curTemp, setTemp, state))

        if state == 'OFF' or state == 'ON' or state == 'CHANGE' or state == 'COMEBACK' or state == 'OUTING':
            tmp_hex = device_list['Thermo'].get('command' + state)
            change = device_list['Thermo'].get('commandNUM')
            tmp_hex = make_hex(k, tmp_hex, change)

            if state == 'CHANGE':
                setT = pad(setTemp)
                chaTnum = OPTION['Thermo'].get('chaTemp')
                tmp_hex = tmp_hex[:chaTnum - 1] + setT + tmp_hex[chaTnum + 1:]

            return checksum(tmp_hex)

        else:
            tmp_hex = device_list['Thermo'].get(state)
            change = device_list['Thermo'].get('stateNUM')
            tmp_hex = make_hex(k, tmp_hex, change)
            setT = pad(setTemp)
            curT = pad(curTemp)
            curTnum = OPTION['Thermo'].get('curTemp')
            setTnum = OPTION['Thermo'].get('setTemp')
            tmp_hex = tmp_hex[:setTnum - 1] + setT + tmp_hex[setTnum + 1:]
            tmp_hex = tmp_hex[:curTnum - 1] + curT + tmp_hex[curTnum + 1:]

            if state == 'stateOFF':
                return checksum(tmp_hex)
            elif state == 'stateON':
                tmp_hex2 = tmp_hex[:3] + str(3) + tmp_hex[4:]
                return [checksum(tmp_hex), checksum(tmp_hex2)]
            else:
                return None

    def make_device_info(dev_name, device):
        num = device.get('Number', 0)
        if num > 0:
            arr = {
                k + 1: {
                    cmd + onoff: make_hex(k, device.get(cmd + onoff), device.get(cmd + 'NUM'))
                    for cmd in ['command', 'state'] 
                    for onoff in ['ON', 'OFF']
                } 
                for k in range(num)
            }

            if dev_name == 'Fan':
                tmp_hex = arr[1]['stateON']
                change = device_list['Fan'].get('speedNUM')
                arr[1]['stateON'] = [make_hex(k, tmp_hex, change) for k in range(3)]
                tmp_hex = device_list['Fan'].get('commandCHANGE')
                arr[1]['CHANGE'] = [make_hex(k, tmp_hex, change) for k in range(3)]

            arr['Num'] = num
            return arr

        else:
            return None

    async def recv_from_HA(topics, value):
        if mqtt_log:
            log('[LOG] HA ->> : {} -> {}'.format('/'.join(topics), value))

        #device = device.split('_')[1]
        # 호를 제거한다.
        topics[1] = topics[1].replace(tsHo + '_', '')

        device = topics[1][:-1]

        if device in DEVICE_LISTS:
            key = topics[1] + topics[2]
            num = topics[1][-1]
            idx = int(num)
            cur_state = HOMESTATE.get(key)
            value = 'ON' if value == 'heat' else value.upper()

            log('[DC] device = {}, key = {}, num = {}, idx = {}, cur_state = {}, value = {}'.format(device, key, num, idx, cur_state, value))

            if cur_state:
                # PASS
                if 'value' == cur_state:
                    if debug:
                        log('[DEBUG] {} is already set: {}'.format(key, value))
                else:
                    if device == 'Thermo':
                        curTemp = HOMESTATE.get(topics[1] + 'curTemp')
                        setTemp = HOMESTATE.get(topics[1] + 'setTemp')

                        log('[DC] device = {}, curTemp = {}, setTemp = {}, topics[1] = {}, topics[2] = {}'.format(device, curTemp, setTemp, topics[1], topics[2]))

                        if topics[2] == 'power':
                            sendcmd = make_hex_temp(idx - 1, curTemp, setTemp, value)
                            recvcmd = [sendcmd]

                            if sendcmd:
                                QUEUE.append({'sendcmd': sendcmd, 'recvcmd': recvcmd, 'count': 1})
                                if debug:
                                    log('[DEBUG] Queued ::: sendcmd: {}, recvcmd: {}'.format(sendcmd, recvcmd))

                        elif topics[2] == 'setTemp':
                            value = int(float(value))
                            # PASS
                            if 'value' == int(setTemp):
                                if debug:
                                    log('[DEBUG] {} is already set: {}'.format(topics[1], value))
                            else:
                                setTemp = value
                                sendcmd = make_hex_temp(idx - 1, curTemp, setTemp, 'CHANGE')
                                recvcmd = [make_hex_temp(idx - 1, curTemp, setTemp, 'stateON')]

                                if sendcmd:
                                    QUEUE.append({'sendcmd': sendcmd, 'recvcmd': recvcmd, 'count': 1})
                                    if debug:
                                        log('[DEBUG] Queued ::: sendcmd: {}, recvcmd: {}'.format(sendcmd, recvcmd))
                                else:
                                    log ('[DC] sendcmd = {}'.format(sendcmd))

                    else:
                        sendcmd = DEVICE_LISTS[device][idx].get('command' + value)
                        if sendcmd:
                            recvcmd = [DEVICE_LISTS[device][idx].get('state' + value, 'NULL')]
                            QUEUE.append({'sendcmd': sendcmd, 'recvcmd': recvcmd, 'count': 0})
                            if debug:
                                log('[DEBUG] Queued ::: sendcmd: {}, recvcmd: {}'.format(sendcmd, recvcmd))
                        else:
                            if debug:
                                log('[DEBUG] No sendcmd for {}'.format('/'.join(topics)))
            else:
                if debug:
                    log('[DEBUG] There is no command about {}'.format('/'.join(topics)))
        else:
            if debug:
                log('[DEBUG] Not found Device {} for {}'.format(device, '/'.join(topics)))

    async def slice_raw_data(raw_data):
        if elfin_log:
            log('[SIGNAL] recv : {}'.format(raw_data))

        # if COLLECTDATA['cond']:
        #     if len(COLLECTDATA['data']) < 50:
        #         if data not in COLLECTDATA['data']:
        #             COLLECTDATA['data'].add(data)
        #     else:
        #         COLLECTDATA['cond'] = False
        #         with open(share_dir + '/collected_signal.txt', 'w', encoding='utf-8') as make_file:
        #             json.dump(COLLECTDATA['data'], make_file, indent="\t")
        #             log('[Complete] Collect 50 signals. See : /share/collected_signal.txt')
        #         COLLECTDATA['data'] = None

        cors = [recv_from_elfin(raw_data[k:k + 16]) for k in range(0, len(raw_data), 16) if raw_data[k:k + 16] == checksum(raw_data[k:k + 16])]
        await asyncio.gather(*cors)

    async def recv_from_elfin(data):
        COLLECTDATA['LastRecv'] = time.time_ns()
        if data:
            for que in QUEUE:
                if data in que['recvcmd']:
                    QUEUE.remove(que)
                    if debug:
                        log('[DEBUG] Found matched hex: {}. Delete a queue: {}'.format(data, que))
                    break

            device_name = prefix_list.get(data[:2])

            if device_name == 'Thermo':
                curTnum = device_list['Thermo']['curTemp']
                setTnum = device_list['Thermo']['setTemp']
                curT = data[curTnum - 1:curTnum + 1]
                setT = data[setTnum - 1:setTnum + 1]
                onoffNUM = device_list['Thermo']['stateONOFFNUM']
                staNUM = device_list['Thermo']['stateNUM']
                index = int(data[staNUM - 1]) - 1
                onoff = 'OFF' 
                outcom = 'OFF'
                
                if int(data[onoffNUM - 1]) > 0:
                    onoff = 'ON'
                if int(data[onoffNUM - 1]) == 4:
                    outcom = 'ON'

                await update_state(device_name, index, onoff)
                await update_outcom(device_name, index, outcom)
                await update_temperature(index, curT, setT)

            else:
                num = DEVICE_LISTS[device_name]['Num']
                state = [DEVICE_LISTS[device_name][k + 1]['stateOFF'] for k in range(num)] + [
                    DEVICE_LISTS[device_name][k + 1]['stateON'] for k in range(num)]
                if data in state:
                    index = state.index(data)
                    onoff, index = ['OFF', index] if index < num else ['ON', index - num]
                    await update_state(device_name, index, onoff)
                else:
                    log("[WARNING] <{}> 기기의 신호를 찾음: {}".format(device_name, data))
                    log('[WARNING] 기기목록에 등록되지 않는 패킷입니다. JSON 파일을 확인하세요..')

    async def update_state(device, idx, onoff):
        state = 'power'
        deviceID = device + str(idx + 1)
        key = deviceID + state

        HOMESTATE[key] = onoff
        topic = STATE_TOPIC.format(tsHo +'_'+ deviceID, state)
        mqtt_client.publish(topic, onoff.encode())

        if mqtt_log:
            log('[LOG] ->> HA : {} >> {}'.format(topic, onoff))

        '''
        if onoff != HOMESTATE.get(key):
            HOMESTATE[key] = onoff
            topic = STATE_TOPIC.format(tsHo +'_'+ deviceID, state)
            mqtt_client.publish(topic, onoff.encode())
            #mqtt_client.publish(topic, onoff.encode(), 2, True)
            if mqtt_log:
                log('[LOG] ->> HA : {} >> {}'.format(topic, onoff))
        else:
            if debug:
                log('[DEBUG] {} is already set: {}'.format(deviceID, onoff))
        '''
        return

    async def update_outcom(device, idx, outcom):
        state = 'state_outing'
        deviceID = device + str(idx + 1)
        key = deviceID + state

        HOMESTATE[key] = outcom
        topic = 'homenet/'+ tsHo +'_'+ deviceID +'/power/state_outing'
        mqtt_client.publish(topic, outcom.encode())
        #mqtt_client.publish(topic, outcom.encode(), 2, True)

        if mqtt_log:
            log('[LOG] ->> HA : {} >> {}'.format(topic, outcom))

        return

    async def update_temperature(idx, curTemp, setTemp):
        deviceID = 'Thermo' + str(idx + 1)
        temperature = {'curTemp': pad(curTemp), 'setTemp': pad(setTemp)}
        for state in temperature:
            key = deviceID + state
            val = temperature[state]

            HOMESTATE[key] = val
            topic = STATE_TOPIC.format(tsHo +'_'+ deviceID, state)
            mqtt_client.publish(topic, val.encode())
            if mqtt_log:
                log('[LOG] ->> HA : {} -> {}'.format(topic, val))

            '''
            if val != HOMESTATE.get(key):
                HOMESTATE[key] = val
                topic = STATE_TOPIC.format(tsHo +'_'+ deviceID, state)
                mqtt_client.publish(topic, val.encode())
                #mqtt_client.publish(topic, val.encode(), 2, True)
                if mqtt_log:
                    log('[LOG] ->> HA : {} -> {}'.format(topic, val))
            else:
                if debug:
                    log('[DEBUG] {} is already set: {}'.format(key, val))
            '''
        return

    def on_connect(client, userdata, flags, rc):
        if rc == 0:
            log("MQTT 접속 완료 = "+ userdata)

            # 장치 구독
            num = DEVICE_LISTS['Thermo']['Num']

            log( "[DC] mqtt subscribe = {}".format(num) )
            log( "[DC] mqtt subscribe = {}".format((HA_TOPIC + '/#')) )
            log( "[DC] mqtt subscribe = {}".format((ELFIN_TOPIC + '/recv')) )
            log( "[DC] mqtt subscribe = {}".format((ELFIN_TOPIC + '/send')) )

            client.subscribe([(HA_TOPIC + '/#', 0), (ELFIN_TOPIC + '/recv', 0), (ELFIN_TOPIC + '/send', 0)])
            
            '''
            if 'Thermo' in DEVICE_LISTS:
                for i in range(num):
                    asyncio.run(update_state('Thermo', i, 'OFF'))

            if 'EV' in DEVICE_LISTS:
                asyncio.run(update_state('EV', 0, 'OFF'))
            '''

        else:
            errcode = {1: 'Connection refused - incorrect protocol version',
                    2: 'Connection refused - invalid client identifier',
                    3: 'Connection refused - server unavailable',
                    4: 'Connection refused - bad username or password',
                    5: 'Connection refused - not authorised'}
            log(errcode[rc])

    def on_message(client, userdata, msg):
        topics = msg.topic.split('/')
        try:
            if topics[0] == HA_TOPIC and topics[-1] == 'command':
                asyncio.run(recv_from_HA(topics, msg.payload.decode('utf-8')))
            elif topics[0] == ELFIN_TOPIC and topics[-1] == 'recv':
                asyncio.run(slice_raw_data(msg.payload.hex().upper()))
        except:
            pass

    async def send_to_elfin():
        while True:
            try:
                if time.time_ns() - COLLECTDATA['LastRecv'] > 10000000000:  # 10s
                    #log('[WARNING] 10초간 신호를 받지 못했습니다. ew11 기기를 재시작합니다.')
                    try:
                        '''
                        elfin_id = config['elfin_id']
                        elfin_password = config['elfin_password']
                        elfin_server = config['elfin_server']
                        ew11 = telnetlib.Telnet(elfin_server)
                        ew11.read_until(b"login:")
                        ew11.write(elfin_id.encode('utf-8') + b'\n')
                        ew11.read_until(b"password:")
                        ew11.write(elfin_password.encode('utf-8') + b'\n')
                        ew11.write('Restart'.encode('utf-8') + b'\n')
                        '''
                        await asyncio.sleep(10)

                    except:
                        log('[WARNING] 기기 재시작 오류! 기기 상태를 확인하세요.')
                    COLLECTDATA['LastRecv'] = time.time_ns()

                elif time.time_ns() - COLLECTDATA['LastRecv'] > 100000000:
                    if QUEUE:
                        send_data = QUEUE.pop(0)

                        if elfin_log: 
                            log('[SIGNAL] send > {} = {}'.format(ELFIN_SEND_TOPIC, send_data))

                        sendBytes = bytes.fromhex(send_data['sendcmd'])
                        recvBytes = None

                        # MQTT에 전송
                        mqtt_client.publish(ELFIN_SEND_TOPIC, sendBytes)
                        #mqtt_client.publish(ELFIN_SEND_TOPIC, sendBytes, 1)
                        #await asyncio.sleep(0.01)

                        # 소켓으로 전송
                        tsElfinIp = OPTION['tsElfinIp']
                        tsElfinPort = OPTION['tsElfinPort']

                        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        client_socket.connect((tsElfinIp, tsElfinPort))
                        client_socket.send(sendBytes)
                        recvBytes = client_socket.recv(512)
                        client_socket.close()

                        send = sendBytes.hex().upper()
                        recv = recvBytes.hex().upper()

                        log("[DC] {}:{} send > {}".format(tsElfinIp, tsElfinPort, send))
                        log("[DC] {}:{} recv < {}".format(tsElfinIp, tsElfinPort, recv))

                        if send_data['recvcmd'] == 'sync':
                            # 02 01 00 00 00 00 00 03
                            # 82 81 01 25 27 00 00 50 
                            #     ^ 0=OFF, 1=ON, 2=외출해제, 4=외출
                            onoff = int(recv[3:4])
                            outcom = int(recv[3:4])

                            dev = int(recv[5:6])
                            curTemp = str(recv[6:8])
                            setTemp = str(recv[8:10])

                            if onoff == 0:
                                onoff = 'OFF'
                            else:
                                onoff = 'ON'

                            if outcom == 4:
                                outcom = "ON"
                            else:
                                outcom = "OFF"

                            log("[DC-sync] dev = {}, onoff = {}, outcom = {}, curTemp = {}, setTemp = {}".format(dev, onoff, outcom, curTemp, setTemp))
                            await update_state('Thermo', dev-1, onoff)
                            await update_outcom('Thermo', dev-1, outcom)
                            await update_temperature(dev-1, curTemp, setTemp)

                        else:
                            await slice_raw_data(recvBytes.hex().upper())

                        # 재시도 횟수
                        #TRYCNT = 1
                        TRYCNT = 3
                        if send_data['count'] < TRYCNT:
                            send_data['count'] = send_data['count'] + 1
                            QUEUE.append(send_data)
                        else:
                            if elfin_log:
                                log('[SIGNAL] Send over {}...'.format(TRYCNT))

            except Exception as err:
                log('[ERROR] send_to_elfin(): {}'.format(err))
                return True

            await asyncio.sleep(0.01)

    def updateSync():
        time.sleep(5)
        while True:
            # 상태정보 업데이트
            num = int(DEVICE_LISTS['Thermo']['Num'])
            
            for i in range(num):
                sendcmd = "020"+ str(i+1) + "00000000000" + str(3+i)
                recvcmd = "sync"
                #log("[DC-sync] sendcmd = {}".format(sendcmd))
                QUEUE.append({'sendcmd': sendcmd, 'recvcmd': recvcmd, 'count': 1})

            time.sleep(5)


#----------------------------------------------------------------------------------------------
    debug = CONFIG['DEBUG']
    mqtt_log = CONFIG['mqtt_log']
    elfin_log = CONFIG['elfin_log']
    find_signal = CONFIG['save_unregistered_signal']

    tsElfinIp = OPTION['tsElfinIp']
    tsElfinPort = OPTION['tsElfinPort']
    tsDong = OPTION['tsDong']
    tsHo = OPTION['tsHo']

    log( "[DC] debug = {}".format(debug) )
    log( "[DC] mqtt_log = {}".format(mqtt_log) )
    log( "[DC] elfin_log = {}".format(elfin_log) )
    log( "[DC] find_signal = {}".format(find_signal) )

    log( "[DC] tsElfinIp = {}".format(tsElfinIp) )
    log( "[DC] tsElfinPort = {}".format(tsElfinPort) )
    log( "[DC] tsDong = {}".format(tsDong) )
    log( "[DC] tsHo = {}".format(tsHo) )

    # 토픽 설정 
    HA_TOPIC = 'homenet'
    STATE_TOPIC = HA_TOPIC + '/{}/{}/state'
    ELFIN_TOPIC = tsHo
    ELFIN_SEND_TOPIC = ELFIN_TOPIC + '/send'
    DEVICE_LISTS = {}

    for name in device_list:
        log('[DC] make_device_info : ' + name)
        device_info = make_device_info(name, device_list[name])
        if device_info:
            DEVICE_LISTS[name] = device_info

    prefix_list = {}
    log('-------------------------')
    log('등록된 기기 목록 DEVICE_LISTS')
    log('-------------------------')
    for name in DEVICE_LISTS:
        state = DEVICE_LISTS[name][1].get('stateON')
        if state:
            prefix = state[0][:2] if isinstance(state, list) else state[:2]
            prefix_list[prefix] = name
        log('{}: {}'.format(name, DEVICE_LISTS[name]))
    log('----------------------')

    HOMESTATE = {}
    QUEUE = []
    COLLECTDATA = {'cond': find_signal, 'data': set(), 'EVtime': time.time(), 'LastRecv': time.time_ns()}
    if find_signal:
        log('[LOG] 신호를 수집 중..')

    # MQTT 서버 접속 설정
    tsMqttIp = CONFIG['mqtt_server']
    tsMqttId = CONFIG['mqtt_id']
    tsMqttPw = CONFIG['mqtt_password']
    log("[DC] mqtt_ip = " + tsMqttIp)
    log("[DC] mqtt_id = " + tsMqttId)
    log("[DC] mqtt_pw = " + tsMqttPw)

    mqtt_client = mqtt.Client(tsHo + "-mqtt")
    mqtt_client.username_pw_set(tsMqttId, tsMqttPw)
    mqtt_client.user_data_set(tsHo)
    mqtt_client.on_connect = on_connect
    mqtt_client.on_message = on_message
    mqtt_client.connect_async(host=tsMqttIp, keepalive=0)
    mqtt_client.loop_start()

    # # 동기화 스레드 생성
    # thread = threading.Thread(target=updateSync)
    # thread.start()

    # #loop = asyncio.get_event_loop()
    # loop = asyncio.new_event_loop()
    # asyncio.set_event_loop(loop)
    # loop.run_until_complete(send_to_elfin())

    # log("end do_work")

    # loop.close()

    # 동기화 스레드 생성 (무한루프)
    isSyncLoop = True
    while isSyncLoop:
        log("[DC] Run - updateSync")
        thread = threading.Thread(target=updateSync)
        thread.start()
        syncLoop = asyncio.new_event_loop()
        asyncio.set_event_loop(syncLoop)
        syncLoop.run_until_complete(send_to_elfin())
        syncLoop.close()
        log("[DC] End - updateSync")
        time.sleep(10) # 10초후에 재시작
    

    mqtt_client.loop_stop()
#----------------------------------------------------------------------------------------------

if __name__ == '__main__':

    with open(config_dir + '/options.json') as file:
        CONFIG = json.load(file)

    try:
        pathFoundDevice = share_dir + '/seik_found_device.json'
        with open(pathFoundDevice) as file:
            log('기기 정보 파일을 찾음: ' + pathFoundDevice)
            OPTION = json.load(file)

    except IOError:
        log('기기 정보 파일이 없습니다: ' + pathFoundDevice)
        #OPTION = find_device(CONFIG)

    log( "[DC] json = {}".format(OPTION))

    # 다중 처리 
    device = OPTION["device"]

    for idx, item in enumerate(device):
        log("[DC] item {} = {}".format(idx, item))
        device_list = {}
        device_list["Thermo"] = item["Thermo"]
        log("[DC] device_list = {}".format(device_list))
        thread = threading.Thread(target=main, args=(CONFIG, item, device_list))
        thread.start()
        time.sleep(1)

    while True:
        # 무한루프
        time.sleep(5)
