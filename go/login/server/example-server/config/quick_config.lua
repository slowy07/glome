-- Copyright 2020 Google LLC
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--      https://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- This file pretends to show a simple configuration based on the use of sets to
-- decide if a user has access to a machine, following some simple rules:
--   - A special user can run functions from the command table in either a special machine or a general machine.
--   - A general user can run functions from the command table only in a general machine.
--   - All other commands are blocked.


-- Set is implemented over a hash
function Set (l)
  local set = {}
  for _, v in ipairs(l) do
    set[v] = true
  end
  return set
end


-- List of tables to work with
GeneralMachines = Set{"my-server.local"}
SpecialMachines = Set{"serial-number:1234567890=ABCDFGH/#?"}
GeneralUser = Set{""}  
SpecialUser = Set{"admin"}
Commands = Set{"shell/root", "reboot"}


-- Authotization Function
-- Note that, in the example, empty action is not allowed, but empty user is.
-- This means that default user is allow, while default action isn't.
function auth(user, host_id, host_id_type, action)
  if Commands[action] then
    if SpecialUser[user] and (GeneralMachines[host] or SpecialMachines[host]) then
      return true
    elseif GeneralUser[user] and GeneralMachines[host] then
      return true
    end
  end

  return false
end
