// -*- C++ -*-
// Tunnel
// -------------------------------------
// file       : tunnel.cpp
// author     : Ben Kietzman
// begin      : 2024-08-23
// copyright  : kietzman.org
// email      : ben@kietzman.org
/***********************************************************************
* This program is free software; you can redistribute it and/or modify *
* it under the terms of the GNU General Public License as published by *
* the Free Software Foundation; either version 2 of the License, or    *
* (at your option) any later version.                                  *
***********************************************************************/
// {{{ includes
#include <cerrno>
#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <libssh/libssh.h>
#include <list>
#include <map>
#include <mutex>
#include <netdb.h>
#include <pwd.h>
#include <sstream>
#include <string>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <termios.h>
#include <thread>
#include <unistd.h>
#include <vector>
using namespace std;
// }}}
// {{{ structs
struct connection
{
  ssh_channel channel;
  string strBuffers[2];
};
// }}}
// {{{ prototypes
int authenticateNone(ssh_session session);
int authenticatePassword(ssh_session session);
int authenticateKbdint(ssh_session session);
// }}}
// {{{ main()
int main(int argc, char *argv[])
{
  bool bExit = false;
  ifstream inConf;
  int nPort;
  list<map<string, string> > locals, remotes;
  passwd *pw = getpwuid(getuid());
  string strPrefix = "main()", strProxyCommand, strServer, strUser;
  stringstream ssConf;

  // {{{ configure
  ssConf << pw->pw_dir << "/.tunnel";
  inConf.open(ssConf.str().c_str());
  if (inConf)
  {
    bool bFirst = true;
    string strLine;
    while (getline(inConf, strLine))
    {
      stringstream ssLine(strLine);
      if (bFirst)
      {
        bFirst = false;
        ssLine >> strServer >> nPort >> strUser;
        if (getline(ssLine, strProxyCommand) && !strProxyCommand.empty())
        {
          bool bDone = false;
          for (size_t i = 0; !bDone && i < strProxyCommand.size(); i++)
          {
            if (isspace(strProxyCommand[i]))
            {
              strProxyCommand.erase(i--, 1);
            }
            else
            {
              bDone = true;
            }
          }
        }
      }
      else
      {
        string strLocalPort, strRemotePort, strType, strTypeServer;
        ssLine >> strType >> strLocalPort >> strTypeServer >> strRemotePort;
        if (strType == "local")
        {
          locals.push_back({{"LocalPort", strLocalPort}, {"RemoteServer", strTypeServer}, {"RemotePort", strRemotePort}});
        }
        else if (strType == "remote")
        {
          remotes.push_back({{"LocalServer", strTypeServer}, {"LocalPort", strLocalPort}, {"RemotePort", strRemotePort}});
        }
        else
        {
          cerr << strPrefix << ":  Please provide a valid type:  local, remote.";
        }
      }
    }
  }
  else
  {
    cerr << strPrefix << "->ifstream::open(" << errno << "):  " << strerror(errno) << endl;
  }
  inConf.close();
  // }}}
  while (true)
  {
    ssh_session session;
    if ((session = ssh_new()) != NULL)
    {
      cout << "ssh_new():  Initialized session." << endl;
      ssh_options_set(session, SSH_OPTIONS_HOST, strServer.c_str());
      ssh_options_set(session, SSH_OPTIONS_PORT, &nPort);
      if (!strProxyCommand.empty())
      {
        ssh_options_set(session, SSH_OPTIONS_PROXYCOMMAND, strProxyCommand.c_str());
      }
      ssh_options_set(session, SSH_OPTIONS_USER, strUser.c_str());
      if (ssh_connect(session) == SSH_OK)
      {
        int nMethod;
        cout << "ssh_connect():  Connected session." << endl;
        ssh_userauth_none(session, NULL);
        nMethod = ssh_userauth_list(session, NULL);
        if ((nMethod & SSH_AUTH_METHOD_PUBLICKEY && ssh_userauth_publickey_auto(session, pw->pw_name, NULL) == SSH_AUTH_SUCCESS))
        //if ((nMethod & SSH_AUTH_METHOD_PUBLICKEY && ssh_userauth_publickey_auto(session, pw->pw_name, NULL) == SSH_AUTH_SUCCESS) || (nMethod & SSH_AUTH_METHOD_INTERACTIVE && authenticateKbdint(session) == SSH_AUTH_SUCCESS) || (nMethod & SSH_AUTH_METHOD_PASSWORD && authenticatePassword(session) == SSH_AUTH_SUCCESS))
        {
          bool bExit = false;
          char szBuffer[65536];
          int fdSession = ssh_get_fd(session), nReturn;
          list<int> removals;
          map<int, map<string, string> > locs, rems;
          map<int, connection> conns;
          cout << "ssh_userauth_publickey_auto():  Authenticated session." << endl;
          // {{{ local
          for (auto &local : locals)
          {
            addrinfo hints, *result;
            bool bBound[3] = {false, false, false};
            int fdSocket, nReturn;
            stringstream ssIdentity;
            ssIdentity << "local," << local["LocalPort"] << "," << local["RemoteServer"] << "," << local["RemotePort"];
            memset(&hints, 0, sizeof(addrinfo));
            hints.ai_family = AF_INET6;
            hints.ai_socktype = SOCK_STREAM;
            hints.ai_flags = AI_PASSIVE;
            if ((nReturn = getaddrinfo(NULL, local["LocalPort"].c_str(), &hints, &result)) == 0)
            {
              addrinfo *rp;
              bBound[0] = true;
              for (rp = result; !bBound[2] && rp != NULL; rp = rp->ai_next)
              {
                bBound[1] = false;
                if ((fdSocket = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) >= 0)
                {
                  int nOn = 1;
                  bBound[1] = true;
                  setsockopt(fdSocket, SOL_SOCKET, SO_REUSEADDR, (char *)&nOn, sizeof(nOn));
                  if (bind(fdSocket, rp->ai_addr, rp->ai_addrlen) == 0)
                  {
                    bBound[2] = true;
                  }
                  else
                  {
                    close(fdSocket);
                  }
                }
              }
              freeaddrinfo(result);
            }
            if (bBound[2])
            {
              cout << strPrefix << "->bind() [" << ssIdentity.str() << "]:  Bound socket." << endl;
              if (listen(fdSocket, SOMAXCONN) == 0)
              {
                long lArg = fcntl(fdSocket, F_GETFL, NULL);
                cout << strPrefix << "->listen() [" << ssIdentity.str() << "]:  Listening to socket." << endl;
                lArg |= O_NONBLOCK;
                fcntl(fdSocket, F_SETFL, lArg);
                locs[fdSocket] = {{"lport", local["LocalPort"]}, {"port", local["RemotePort"]}, {"server", local["RemoteServer"]}};
              }
              else
              {
                cout << strPrefix << "->listen(" << errno << ") error [" << ssIdentity.str() << "]:  " << strerror(errno) << endl;
              }
            }
            else if (!bBound[0])
            {
              cerr << strPrefix << "->getaddrinfo(" << nReturn << ") error [" << ssIdentity.str() << "]:  " << gai_strerror(nReturn) << endl;
            }
            else
            {
              cerr << strPrefix << "->" << ((!bBound[1])?"socket":"bind") << "(" << errno << ") error [" << ssIdentity.str() << "]:  " << strerror(errno) << endl;
            }
          }
          // }}}
          // {{{ remote
          for (auto &remote : remotes)
          {
            int nRemotePort, nReturn;
            stringstream ssIdentity, ssRemotePort(remote["RemotePort"]);
            ssIdentity << "remote," << remote["LocalServer"] << "," << remote["LocalPort"] << "," << remote["RemotePort"];
            ssRemotePort >> nRemotePort;
            if ((nReturn = ssh_channel_listen_forward(session, "localhost", nRemotePort, NULL)) == SSH_OK)
            {
              cout << strPrefix << "->ssh_channel_listen_forward() [" << ssIdentity.str() << "]:  Listening to socket." << endl;
              rems[nRemotePort] = {{"port", remote["LocalPort"]}, {"server", remote["LocalServer"]}};
            }
            else
            {
              cerr << strPrefix << "->ssh_channel_listen_forward() error [" << ssIdentity.str() << "]:  " << ssh_get_error(session) << endl;
            }
          }
          // }}}
          while (!bExit)
          {
            bool bAccepted = true;
            fd_set fds;
            int fdMax = 0;
            size_t unIndex = 0;
            ssh_channel inChannels[conns.size()+1], outChannels[conns.size()+1];
            timeval timeout;
            timeout.tv_sec = 2;
            timeout.tv_usec = 0;
            FD_ZERO(&fds);
            for (auto &loc : locs)
            {
              FD_SET(loc.first, &fds);
              fdMax = (((loc.first + 1) > fdMax)?loc.first:fdMax) + 1;
            }
            FD_SET(fdSession, &fds);
            fdMax = (((fdSession + 1) > fdMax)?fdSession:fdMax) + 1;
            for (auto &conn : conns)
            {
              inChannels[unIndex++] = conn.second.channel;
              FD_SET(conn.first, &fds);
              fdMax = (((conn.first + 1) > fdMax)?conn.first:fdMax) + 1;
            }
            inChannels[unIndex] = NULL;
            if ((nReturn = ssh_select(inChannels, outChannels, fdMax, &fds, &timeout)) == SSH_OK)
            {
              // {{{ local
              for (auto &loc : locs)
              {
                if (FD_ISSET(loc.first, &fds))
                {
                  int fdClient;
                  sockaddr_in cli_addr;
                  socklen_t clilen = sizeof(cli_addr);
                  if ((fdClient = accept(loc.first, (sockaddr *)&cli_addr, &clilen)) >= 0)
                  {
                    ssh_channel channel;
                    cout << strPrefix << "->accept():  Accepted client socket." << endl;
                    if ((channel = ssh_channel_new(session)) != NULL)
                    {
                      int nLocalPort, nRemotePort;
                      stringstream ssLocalPort(loc.second["lport"]), ssRemotePort(loc.second["port"]);
                      cout << strPrefix << "->ssh_channel_new():  Created channel." << endl;
                      ssLocalPort >> nLocalPort;
                      ssRemotePort >> nRemotePort;
                      if (ssh_channel_open_forward(channel, loc.second["server"].c_str(), nRemotePort, "localhost", nLocalPort) == SSH_OK)
                      {
                        conns[fdClient].channel = channel;
                        cout << strPrefix << "->ssh_channel_open_forward():  Opened channel." << endl;
                      }
                      else
                      {
                        cerr << strPrefix << "->ssh_channel_open_forward() error:  " << ssh_get_error(session) << endl;
                        ssh_channel_send_eof(channel);
                        ssh_channel_free(channel);
                        close(fdClient);
                      }
                    }
                    else
                    {
                      cerr << strPrefix << "->ssh_channel_new() error:  " << ssh_get_error(session) << endl;
                    }
                  }
                  else
                  {
                    bExit = true;
                    cerr << strPrefix << "->accept(" << errno << ") error:  " << strerror(errno) << endl;
                  }
                }
              }
              // }}}
              for (auto &conn : conns)
              {
                if (FD_ISSET(conn.first, &fds))
                {
                  if ((nReturn = read(conn.first, &szBuffer, 65536)) > 0)
                  {
                    //cout << strPrefix << "->read():  Read " << nReturn << " bytes." << endl;
                    conn.second.strBuffers[1].append(szBuffer, nReturn);
                  }
                  else
                  {
                    removals.push_back(conn.first);
                    if (nReturn < 0)
                    {
                      cerr << strPrefix << "->read(" << errno << ") error:  " << strerror(errno) << endl;
                    }
                  }
                }
              }
              for (size_t i = 0; i < unIndex; i++)
              {
                if (outChannels[i] != NULL)
                {
                  auto connIter = conns.end();
                  for (auto j = conns.begin(); connIter == conns.end() && j != conns.end(); j++)
                  {
                    if (j->second.channel == outChannels[i])
                    {
                      connIter = j;
                    }
                  }
                  if (connIter != conns.end())
                  {
                    if ((nReturn = ssh_channel_read(connIter->second.channel, szBuffer, 65536, 0)) > 0)
                    {
                      //cout << strPrefix << "->ssh_channel_read():  Read " << nReturn << " bytes." << endl;
                      connIter->second.strBuffers[0].append(szBuffer, nReturn);
                    }
                    else
                    {
                      removals.push_back(connIter->first);
                      if (nReturn < 0)
                      {
                        cerr << strPrefix << "->ssh_channel_read() error:  " << ssh_get_error(session) << endl;
                      }
                    }
                  }
                }
              }
            }
            else if (nReturn != SSH_EINTR)
            {
              cerr << strPrefix << "->ssh_select() error:  " << ssh_get_error(session) << endl;
            }
            for (auto &conn : conns)
            {
              if (!conn.second.strBuffers[0].empty())
              {
                if ((nReturn = write(conn.first, conn.second.strBuffers[0].c_str(), conn.second.strBuffers[0].size())) > 0)
                {
                  //cout << strPrefix << "->write():  Wrote " << nReturn << " bytes." << endl;
                  conn.second.strBuffers[0].erase(0, nReturn);
                }
                else if (nReturn < 0)
                {
                  removals.push_back(conn.first);
                  cerr << strPrefix << "->write(" << errno << ") error:  " << strerror(errno) << endl;
                }
              }
              if (!conn.second.strBuffers[1].empty())
              {
                if ((nReturn = ssh_channel_write(conn.second.channel, conn.second.strBuffers[1].c_str(), conn.second.strBuffers[1].size())) > 0)
                {
                  //cout << strPrefix << "->ssh_channel_write():  Wrote " << nReturn << " bytes." << endl;
                  conn.second.strBuffers[1].erase(0, nReturn);
                }
                else if (nReturn < 0)
                {
                  removals.push_back(conn.first);
                  cerr << strPrefix << "->ssh_channel_write() error:  " << ssh_get_error(session) << endl;
                }
              }
            }
            removals.sort();
            removals.unique();
            while (!removals.empty())
            {
              ssh_channel_send_eof(conns[removals.front()].channel);
              ssh_channel_free(conns[removals.front()].channel);
              cout << strPrefix << "->ssh_channel_free():  Freed channel." << endl;
              close(removals.front());
              cout << strPrefix << "->close():  Closed client socket." << endl;
              conns.erase(removals.front());
              removals.pop_front();
            }
            // {{{ remote
            while (bAccepted)
            {
              int nPort;
              ssh_channel channel;
              bAccepted = false;
              if ((channel = ssh_channel_accept_forward(session, 1, &nPort)) != NULL)
              {
                if (rems.find(nPort) != rems.end())
                {
                  addrinfo hints, *result;
                  bool bConnected[3] = {false, false, false};
                  int fdClient;
                  bAccepted = true;
                  memset(&hints, 0, sizeof(addrinfo));
                  hints.ai_family = AF_UNSPEC;
                  hints.ai_socktype = SOCK_STREAM;
                  if ((nReturn = getaddrinfo(rems[nPort]["server"].c_str(), rems[nPort]["port"].c_str(), &hints, &result)) == 0)
                  {
                    bConnected[0] = true;
                    for (addrinfo *rp = result; !bConnected[2] && rp != NULL; rp = rp->ai_next)
                    {
                      bConnected[1] = false;
                      if ((fdClient = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) >= 0)
                      {
                        bConnected[1] = true;
                        if (connect(fdClient, rp->ai_addr, rp->ai_addrlen) == 0)
                        {
                          bConnected[2] = true;
                        }
                        else
                        {
                          close(fdClient);
                        }
                      }
                    }
                    freeaddrinfo(result);
                  }
                  if (bConnected[2])
                  {
                    long lArg = fcntl(fdClient, F_GETFL, NULL);
                    lArg |= O_NONBLOCK;
                    fcntl(fdClient, F_SETFL, lArg);
                    conns[fdClient].channel = channel;
                    cout << strPrefix << "->connect():  Connected socket." << endl;
                  }
                  else
                  {
                    if (!bConnected[0])
                    {
                      cerr << strPrefix << "->getaddrinfo(" << nReturn << ") error:  " << gai_strerror(nReturn) << endl;
                    }
                    else
                    {
                      cerr << strPrefix << "->" << ((!bConnected[1])?"socket":"connect") << "(" << errno << ") error:  " << strerror(errno) << endl;
                    }
                    ssh_channel_send_eof(channel);
                    ssh_channel_free(channel);
                  }
                }
                else
                {
                  cerr << strPrefix << "->ssh_channel_accept_forward() error:  Invalid port." << endl;
                  ssh_channel_send_eof(channel);
                  ssh_channel_free(channel);
                }
              }
            }
            // }}}
          }
          for (auto &loc : locs)
          {
            close(loc.first);
            cout << strPrefix << "->close():  Closed listening socket." << endl;
          }
          for (auto &conn : conns)
          {
            ssh_channel_send_eof(conn.second.channel);
            ssh_channel_free(conn.second.channel);
            cout << strPrefix << "->ssh_channel_free():  Freed channel." << endl;
            close(conn.first);
            cout << strPrefix << "->close():  Closed client socket." << endl;
          }
        }
        else
        {
          cerr << "authenticate*() error:  " << ssh_get_error(session) << endl;
        }
        ssh_disconnect(session);
        cout << "ssh_disconnect():  Disconnected session." << endl;
      }
      else
      {
        cerr << "ssh_connect() error:  " << ssh_get_error(session) << endl;
      }
      ssh_free(session);
      cout << "ssh_free():  Freed session." << endl;
    }
    else
    {
      cerr << "ssh_new() error:  Failed to initialize SSH session." << endl;
    }
    if (!bExit)
    {
      sleep(30);
    }
  }

  return 0;
}
// }}}
// {{{ authenticate
// {{{ authenticateNone()
int authenticateNone(ssh_session session)
{
  return ssh_userauth_none(session, NULL);
}
// }}}
// {{{ authenticatePassword()
int authenticatePassword(ssh_session session)
{
  string strPassword;
  termios term;

  cout << "Password:  " << flush;
  tcgetattr(0, &term);
  term.c_lflag &= ~ECHO;
  tcsetattr(0, 0, &term);
  cin >> strPassword;
  term.c_lflag |= ECHO;
  tcsetattr(0, 0, &term);

  return ssh_userauth_password(session, NULL, strPassword.c_str());
}
// }}}
// {{{ authenticateKbdint()
int authenticateKbdint(ssh_session session)
{
  int nReturn;

  while ((nReturn = ssh_userauth_kbdint(session, NULL, NULL)) == SSH_AUTH_INFO)
  {
    int nPrompts = ssh_userauth_kbdint_getnprompts(session);
    for (int i = 0; i < nPrompts; i++)
    {
      char cEcho;
      string strPrompt = ssh_userauth_kbdint_getprompt(session, i, &cEcho);
      if (strPrompt == "Password: ")
      {
        string strPassword;
        termios term;
        cout << "Password:  " << flush;
        tcgetattr(0, &term);
        term.c_lflag &= ~ECHO;
        tcsetattr(0, 0, &term);
        cin >> strPassword;
        term.c_lflag |= ECHO;
        tcsetattr(0, 0, &term);
        if (ssh_userauth_kbdint_setanswer(session, i, strPassword.c_str()) < 0)
        {
          return SSH_AUTH_ERROR;
        }
      }
    }
  }

  return nReturn;
}
// }}}
// }}}
